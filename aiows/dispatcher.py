"""
Event dispatcher implementation
"""

import asyncio
import copy
import logging
import threading
import time
from .router import Router
from .websocket import WebSocket  
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage
from .exceptions import MessageValidationError, MiddlewareError, ConnectionError, AiowsException
from .middleware.base import BaseMiddleware
from typing import List, Callable, Any, Optional


class DispatcherErrorMetrics:
    """Error metrics collector for dispatcher operations"""
    def __init__(self):
        self.middleware_errors = 0
        self.handler_errors = 0
        self.parsing_errors = 0
        self.critical_errors = 0
        self.timeout_errors = 0
        self.validation_errors = 0
        self.connection_errors = 0
        self.unexpected_errors = 0
        self.last_error_time = 0
    
    def increment(self, error_type: str):
        if hasattr(self, f"{error_type}_errors"):
            setattr(self, f"{error_type}_errors", getattr(self, f"{error_type}_errors") + 1)
        self.last_error_time = time.time()

dispatcher_error_metrics = DispatcherErrorMetrics()


class MessageDispatcher:
    """Dispatcher for handling WebSocket events and messages"""
    
    def __init__(self, router: Router):
        self.router = router
        self._middleware: List[BaseMiddleware] = []
        self._middleware_lock = threading.Lock()
        self.logger = logging.getLogger("aiows.dispatcher")
        self._consecutive_errors = 0
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        with self._middleware_lock:
            self._middleware.append(middleware)
    
    def _log_error_with_context(self, error: Exception, operation: str, 
                               websocket: Optional[WebSocket] = None, 
                               additional_context: dict = None):
        context = {
            'operation': operation,
            'error_type': type(error).__name__,
            'consecutive_errors': self._consecutive_errors,
            'timestamp': time.time(),
        }
        
        if websocket:
            context.update({
                'remote_address': websocket.remote_address,
                'websocket_closed': websocket.closed,
            })
        
        if additional_context:
            context.update(additional_context)
        
        self.logger.error(f"Dispatcher {operation} error: {error}", extra={'context': context})
    
    def _parse_message_safely(self, message_data: dict) -> BaseMessage:
        try:
            safe_data = copy.deepcopy(message_data)
            message_type = safe_data.get('type')
            
            if message_type == 'chat':
                return ChatMessage(**safe_data)
            elif message_type == 'join_room':
                return JoinRoomMessage(**safe_data)
            elif message_type == 'game_action':
                return GameActionMessage(**safe_data)
            else:
                return BaseMessage(**safe_data)
                
        except (TypeError, ValueError, KeyError) as e:
            dispatcher_error_metrics.increment('parsing')
            self._log_error_with_context(e, 'message_parsing', 
                                       additional_context={'message_type': message_data.get('type', 'unknown')})
            raise MessageValidationError(f"Failed to parse message: {str(e)}")
        
        except RecursionError as e:
            dispatcher_error_metrics.increment('parsing')
            self._log_error_with_context(e, 'message_parsing', 
                                       additional_context={'message_type': message_data.get('type', 'unknown'), 
                                                         'recursion_error': True})
            raise MessageValidationError(f"Message structure too complex: {str(e)}")
        
        except MemoryError as e:
            dispatcher_error_metrics.increment('critical')
            self.logger.critical(f"Memory error during message parsing: {e}")
            raise
        
        except Exception as e:
            dispatcher_error_metrics.increment('unexpected')
            self._log_error_with_context(e, 'message_parsing', 
                                       additional_context={'message_type': message_data.get('type', 'unknown'), 
                                                         'unexpected': True})
            self.logger.critical(f"Unexpected error during message parsing: {type(e).__name__}: {e}")
            raise MessageValidationError(f"Unexpected parsing error: {str(e)}")
    
    async def _handle_middleware_exception(
        self, 
        exception: Exception, 
        middleware: BaseMiddleware, 
        event_type: str, 
        websocket: Optional[WebSocket] = None
    ) -> bool:
        middleware_name = middleware.__class__.__name__
        
        self._consecutive_errors += 1
        
        if isinstance(exception, MiddlewareError):
            dispatcher_error_metrics.increment('middleware')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name})
            if "auth" in middleware_name.lower() or "security" in middleware_name.lower():
                self.logger.warning(f"Critical middleware {middleware_name} failed, interrupting chain")
                return False
            return True
            
        elif isinstance(exception, ConnectionError):
            dispatcher_error_metrics.increment('connection')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name})
            return False
            
        elif isinstance(exception, MessageValidationError):
            dispatcher_error_metrics.increment('validation')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name})
            if event_type == "message":
                return False
            return True
            
        elif isinstance(exception, AiowsException):
            dispatcher_error_metrics.increment('middleware')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name})
            return True
        
        elif isinstance(exception, (asyncio.CancelledError, asyncio.TimeoutError)):
            dispatcher_error_metrics.increment('timeout')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name, 'async_error': True})
            return False
            
        elif isinstance(exception, (MemoryError, OSError)):
            dispatcher_error_metrics.increment('critical')
            self.logger.critical(f"System error in {middleware_name} during {event_type}: {str(exception)}")
            return False
            
        else:
            dispatcher_error_metrics.increment('unexpected')
            self._log_error_with_context(exception, f"middleware_{event_type}", websocket, 
                                       {'middleware_name': middleware_name, 'unexpected': True})
            self.logger.exception(f"Unexpected error in {middleware_name} during {event_type}: {str(exception)}")
            return True
    
    async def _execute_connect_chain(self, websocket: WebSocket) -> None:
        for handler in self.router._connect_handlers:
            try:
                await handler(websocket)
                self._consecutive_errors = max(0, self._consecutive_errors - 1)
                
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('timeout')
                raise
            
            except (MemoryError, OSError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('critical')
                self._log_error_with_context(e, 'connect_handler', websocket, {'critical': True})
                raise
            
            except (ConnectionError, MessageValidationError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('handler')
                self._log_error_with_context(e, 'connect_handler', websocket)
                
            except Exception as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('unexpected')
                self._log_error_with_context(e, 'connect_handler', websocket, {'unexpected': True})
                self.logger.warning(f"Unexpected error in connect handler: {type(e).__name__}: {e}")
    
    async def _execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        for handler in self.router._disconnect_handlers:
            try:
                await handler(websocket, reason)
                self._consecutive_errors = max(0, self._consecutive_errors - 1)
                
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('timeout')
                raise
            
            except (MemoryError, OSError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('critical')
                self._log_error_with_context(e, 'disconnect_handler', websocket, 
                                           {'critical': True, 'reason': reason})
                raise
            
            except (ConnectionError, MessageValidationError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('handler')
                self._log_error_with_context(e, 'disconnect_handler', websocket, {'reason': reason})
                
            except Exception as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('unexpected')
                self._log_error_with_context(e, 'disconnect_handler', websocket, 
                                           {'unexpected': True, 'reason': reason})
                self.logger.warning(f"Unexpected error in disconnect handler: {type(e).__name__}: {e}")
    
    async def _execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        message = self._parse_message_safely(message_data)
        message_type = message.type
        
        suitable_handler = None
        
        for handler_info in self.router._message_handlers:
            handler_message_type = handler_info.get('message_type')
            
            if handler_message_type is None or handler_message_type == message_type:
                suitable_handler = handler_info.get('handler')
                break
        
        if suitable_handler:
            try:
                await suitable_handler(websocket, message)
                self._consecutive_errors = max(0, self._consecutive_errors - 1)
                
            except (asyncio.CancelledError, asyncio.TimeoutError):
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('timeout')
                raise
            
            except (MemoryError, OSError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('critical')
                self._log_error_with_context(e, 'message_handler', websocket, 
                                           {'critical': True, 'message_type': message_type})
                raise
            
            except (ConnectionError, MessageValidationError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('handler')
                self._log_error_with_context(e, 'message_handler', websocket, {'message_type': message_type})
                
            except Exception as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('unexpected')
                self._log_error_with_context(e, 'message_handler', websocket, 
                                           {'unexpected': True, 'message_type': message_type})
                self.logger.warning(f"Unexpected error in message handler: {type(e).__name__}: {e}")
        else:
            self.logger.warning(f"No handler found for message type: {message_type}")

    async def dispatch_connect(self, websocket: WebSocket) -> None:
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_connect_chain(websocket)

    async def dispatch_disconnect(self, websocket: WebSocket, reason: str) -> None:
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_disconnect_chain(websocket, reason)

    async def dispatch_message(self, websocket: WebSocket, message_data: dict) -> None:
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_message_chain(websocket, message_data)
    
    @property
    def error_metrics(self) -> DispatcherErrorMetrics:
        return dispatcher_error_metrics


class _MiddlewareChainExecutor:
    def __init__(self, middleware_list: List[BaseMiddleware], dispatcher: MessageDispatcher):
        self.middleware_list = middleware_list
        self.dispatcher = dispatcher
    
    def cleanup(self) -> None:
        self.middleware_list.clear()
        self.dispatcher = None
    
    async def execute_connect_chain(self, websocket: WebSocket) -> None:
        try:
            await self._execute_chain_iterative("connect", websocket)
        finally:
            self.cleanup()
    
    async def execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        try:
            await self._execute_chain_iterative("disconnect", websocket, reason)
        finally:
            self.cleanup()
    
    async def execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        try:
            await self._execute_chain_iterative("message", websocket, message_data)
        finally:
            self.cleanup()
    
    async def _execute_chain_iterative(self, event_type: str, *args) -> None:
        if not self.middleware_list:
            await self._execute_final_handler(event_type, *args)
            return
        
        context = _MiddlewareExecutionContext(
            self.middleware_list,
            self.dispatcher,
            event_type,
            args
        )
        
        await context.execute_from_index(0)
    
    async def _execute_final_handler(self, event_type: str, *args) -> None:
        if event_type == "connect":
            await self.dispatcher._execute_connect_chain(*args)
        elif event_type == "disconnect":
            await self.dispatcher._execute_disconnect_chain(*args)
        elif event_type == "message":
            await self.dispatcher._execute_message_chain(*args)
        else:
            raise ValueError(f"Unknown event type: {event_type}")


class _MiddlewareExecutionContext:
    def __init__(self, middleware_list: List[BaseMiddleware], dispatcher: MessageDispatcher, event_type: str, args: tuple):
        self.middleware_list = middleware_list
        self.dispatcher = dispatcher
        self.event_type = event_type
        self.args = args
    
    async def execute_from_index(self, index: int) -> None:
        if index >= len(self.middleware_list):
            await self._execute_final_handler()
            return
        
        current_middleware = self.middleware_list[index]
        
        try:
            next_handler = _NextHandler(self, index + 1)
            
            if self.event_type == "connect":
                await current_middleware.on_connect(next_handler.call, *self.args)
            elif self.event_type == "disconnect":
                await current_middleware.on_disconnect(next_handler.call, *self.args)
            elif self.event_type == "message":
                await current_middleware.on_message(next_handler.call, *self.args)
            else:
                raise ValueError(f"Unknown event type: {self.event_type}")
                
        except Exception as e:
            websocket = self.args[0] if self.args and hasattr(self.args[0], 'context') else None
            
            should_continue = await self.dispatcher._handle_middleware_exception(
                e, current_middleware, self.event_type, websocket
            )
            
            if not should_continue:
                if self.event_type == "connect" and websocket and not websocket.closed:
                    try:
                        await websocket.close(code=1011, reason="Server error")
                    except Exception:
                        pass
                return
            
            await self.execute_from_index(index + 1)
    
    async def _execute_final_handler(self) -> None:
        if self.event_type == "connect":
            await self.dispatcher._execute_connect_chain(*self.args)
        elif self.event_type == "disconnect":
            await self.dispatcher._execute_disconnect_chain(*self.args)
        elif self.event_type == "message":
            await self.dispatcher._execute_message_chain(*self.args)
        else:
            raise ValueError(f"Unknown event type: {self.event_type}")


class _NextHandler:
    def __init__(self, context: _MiddlewareExecutionContext, next_index: int):
        self.context = context
        self.next_index = next_index
    
    async def call(self, *args) -> None:
        if args:
            self.context.args = args
        
        await self.context.execute_from_index(self.next_index)
