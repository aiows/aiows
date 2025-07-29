"""
Event dispatcher implementation
"""

import asyncio
import logging
import threading
import time
from .router import Router
from .websocket import WebSocket  
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage, EventType
from .exceptions import (
    MessageValidationError, MiddlewareError, ConnectionError, AiowsException,
    ErrorCategory, ErrorContext, ErrorCategorizer
)
from .middleware.base import BaseMiddleware
from typing import List, Optional, Dict, Any


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
        
        self.fatal_errors = 0
        self.recoverable_errors = 0
        self.client_errors = 0
        self.server_errors = 0
    
    def increment(self, error_type: str):
        if hasattr(self, f"{error_type}_errors"):
            setattr(self, f"{error_type}_errors", getattr(self, f"{error_type}_errors") + 1)
        self.last_error_time = time.time()
    
    def increment_category(self, category: ErrorCategory):
        category_map = {
            ErrorCategory.FATAL: 'fatal',
            ErrorCategory.RECOVERABLE: 'recoverable', 
            ErrorCategory.CLIENT_ERROR: 'client',
            ErrorCategory.SERVER_ERROR: 'server'
        }
        
        category_name = category_map.get(category, 'server')
        self.increment(category_name)


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
    
    def remove_middleware(self, middleware: BaseMiddleware) -> bool:
        with self._middleware_lock:
            try:
                self._middleware.remove(middleware)
                return True
            except ValueError:
                return False
    
    def _create_error_context(self, operation: str, websocket: Optional[WebSocket] = None, 
                             additional_context: Optional[Dict[str, Any]] = None) -> ErrorContext:
        context_data = {
            'consecutive_errors': self._consecutive_errors,
            'timestamp': time.time(),
        }
        
        if websocket:
            context_data.update({
                'remote_address': websocket.remote_address,
                'websocket_closed': websocket.closed,
            })
        
        if additional_context:
            context_data.update(additional_context)
        
        return ErrorContext(
            operation=operation,
            component='dispatcher',
            additional_context=context_data
        )
    
    def _log_error_with_context(self, error: Exception, context: ErrorContext):
        category = ErrorCategorizer.categorize_exception(error)
        log_level = ErrorCategorizer.get_log_level(error)
        
        log_method = getattr(self.logger, log_level, self.logger.error)
        
        message = f"Dispatcher error in {context.operation}: {error}"
        
        extra_data = {
            'error_category': category.value,
            'error_type': type(error).__name__,
            'error_id': context.error_id,
            'context': context.to_dict()
        }
        
        log_method(message, extra=extra_data)
        
        dispatcher_error_metrics.increment_category(category)
    
    def _parse_message_safely(self, message_data: dict) -> BaseMessage:
        context = self._create_error_context('message_parsing', 
                                           additional_context={'message_type': message_data.get('type', 'unknown')})
        
        try:
            message_type = message_data.get('type')
            
            if message_type == 'chat':
                return ChatMessage(**message_data)
            elif message_type == 'join_room':
                return JoinRoomMessage(**message_data)
            elif message_type == 'game_action':
                return GameActionMessage(**message_data)
            else:
                return BaseMessage(**message_data)
                
        except (TypeError, ValueError, KeyError) as e:
            dispatcher_error_metrics.increment('parsing')
            validation_error = MessageValidationError(f"Failed to parse message: {str(e)}")
            self._log_error_with_context(validation_error, context)
            raise validation_error
        
        except RecursionError as e:
            dispatcher_error_metrics.increment('parsing')
            context.additional_context['recursion_error'] = True
            validation_error = MessageValidationError(f"Message structure too complex: {str(e)}")
            self._log_error_with_context(validation_error, context)
            raise validation_error
        
        except MemoryError as e:
            dispatcher_error_metrics.increment('critical')
            self._log_error_with_context(e, context)
            raise
        
        except Exception as e:
            dispatcher_error_metrics.increment('unexpected')
            context.additional_context['unexpected'] = True
            self._log_error_with_context(e, context)
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
        
        context = self._create_error_context(
            f"middleware_{event_type}",
            websocket,
            {'middleware_name': middleware_name}
        )
        
        self._consecutive_errors += 1
        
        category = ErrorCategorizer.categorize_exception(exception)
        should_stop = ErrorCategorizer.should_stop_middleware_chain(exception, middleware_name)
        
        self._log_error_with_context(exception, context)
        
        if category == ErrorCategory.FATAL:
            if isinstance(exception, (MemoryError, OSError)):
                dispatcher_error_metrics.increment('critical')
                self.logger.critical(f"System error in {middleware_name} during {event_type}: {str(exception)}")
            return False
        
        elif category == ErrorCategory.CLIENT_ERROR:
            return False
            
        elif category == ErrorCategory.RECOVERABLE:
            return False
            
        elif category == ErrorCategory.SERVER_ERROR:
            if isinstance(exception, ConnectionError):
                return False
            elif isinstance(exception, MiddlewareError):
                if "auth" in middleware_name.lower() or "security" in middleware_name.lower():
                    self.logger.warning(f"Critical middleware {middleware_name} failed, interrupting chain")
                    return False
                return True
            else:
                return True
        
        return not should_stop
    
    async def _execute_handler_chain_safely(self, handler_type: str, handler_list: List, *args) -> None:
        websocket = args[0] if args and hasattr(args[0], 'context') else None
        
        for handler in handler_list:
            try:
                await handler(*args)
                self._consecutive_errors = max(0, self._consecutive_errors - 1)
                
            except (asyncio.CancelledError, asyncio.TimeoutError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('timeout')
                context = self._create_error_context(f'{handler_type}_handler', websocket)
                self._log_error_with_context(e, context)
                raise
            
            except (MemoryError, OSError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('critical')
                context = self._create_error_context(f'{handler_type}_handler', websocket, {'critical': True})
                self._log_error_with_context(e, context)
                raise
            
            except (ConnectionError, MessageValidationError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('handler')
                context = self._create_error_context(f'{handler_type}_handler', websocket)
                self._log_error_with_context(e, context)
                
            except Exception as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('unexpected')
                context = self._create_error_context(f'{handler_type}_handler', websocket, {'unexpected': True})
                self._log_error_with_context(e, context)
                self.logger.warning(f"Unexpected error in {handler_type} handler: {type(e).__name__}: {e}")
    
    async def _execute_connect_chain(self, websocket: WebSocket) -> None:
        await self._execute_handler_chain_safely('connect', self.router._connect_handlers, websocket)
    
    async def _execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        await self._execute_handler_chain_safely('disconnect', self.router._disconnect_handlers, websocket, reason)
    
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
                
            except (asyncio.CancelledError, asyncio.TimeoutError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('timeout')
                context = self._create_error_context('message_handler', websocket, 
                                                   {'message_type': message_type})
                self._log_error_with_context(e, context)
                raise
            
            except (MemoryError, OSError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('critical')
                context = self._create_error_context('message_handler', websocket, 
                                                   {'critical': True, 'message_type': message_type})
                self._log_error_with_context(e, context)
                raise
            
            except (ConnectionError, MessageValidationError) as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('handler')
                context = self._create_error_context('message_handler', websocket, 
                                                   {'message_type': message_type})
                self._log_error_with_context(e, context)
                
            except Exception as e:
                self._consecutive_errors += 1
                dispatcher_error_metrics.increment('unexpected')
                context = self._create_error_context('message_handler', websocket, 
                                                   {'unexpected': True, 'message_type': message_type})
                self._log_error_with_context(e, context)
                self.logger.warning(f"Unexpected error in message handler: {type(e).__name__}: {e}")
        else:
            self.logger.warning(f"No handler found for message type: {message_type}")

    async def _execute_middleware_chain(self, event_type: EventType, middleware_list: List[BaseMiddleware], *args) -> None:
        middleware_index = 0
        chain_interrupted = False
        
        async def next_handler(*handler_args) -> None:
            nonlocal middleware_index, chain_interrupted
            
            effective_args = handler_args if handler_args else args
            
            if middleware_index < len(middleware_list):
                current_middleware = middleware_list[middleware_index]
                middleware_index += 1
                
                try:
                    if event_type == EventType.CONNECT:
                        await current_middleware.on_connect(next_handler, *effective_args)
                    elif event_type == EventType.DISCONNECT:
                        await current_middleware.on_disconnect(next_handler, *effective_args)
                    elif event_type == EventType.MESSAGE:
                        await current_middleware.on_message(next_handler, *effective_args)
                    else:
                        raise ValueError(f"Unknown event type: {event_type}")
                        
                except Exception as e:
                    websocket = effective_args[0] if effective_args and hasattr(effective_args[0], 'context') else None
                    
                    should_continue = await self._handle_middleware_exception(
                        e, current_middleware, event_type.value, websocket
                    )
                    
                    if not should_continue:
                        chain_interrupted = True
                        if event_type == EventType.CONNECT and websocket and not websocket.closed:
                            try:
                                await websocket.close(code=1011, reason="Server error")
                            except Exception:
                                pass
                        return
                    
                    category = ErrorCategorizer.categorize_exception(e)
                    if category in [ErrorCategory.CLIENT_ERROR, ErrorCategory.RECOVERABLE]:
                        chain_interrupted = True
                        return
                    elif category == ErrorCategory.SERVER_ERROR and isinstance(e, MiddlewareError):
                        middleware_name = current_middleware.__class__.__name__
                        if any(keyword in middleware_name.lower() for keyword in ['auth', 'security']):
                            chain_interrupted = True
                            return
                        await next_handler(*effective_args)
                        return
                    else:
                        chain_interrupted = True
                        return
            else:
                if not chain_interrupted:
                    if event_type == EventType.CONNECT:
                        await self._execute_connect_chain(*effective_args)
                    elif event_type == EventType.DISCONNECT:
                        await self._execute_disconnect_chain(*effective_args)
                    elif event_type == EventType.MESSAGE:
                        await self._execute_message_chain(*effective_args)
        
        await next_handler(*args)

    async def dispatch_connect(self, websocket: WebSocket) -> None:
        with self._middleware_lock:
            middleware_snapshot = tuple(self._middleware)
        
        await self._execute_middleware_chain(EventType.CONNECT, middleware_snapshot, websocket)

    async def dispatch_disconnect(self, websocket: WebSocket, reason: str) -> None:
        with self._middleware_lock:
            middleware_snapshot = tuple(self._middleware)
        
        await self._execute_middleware_chain(EventType.DISCONNECT, middleware_snapshot, websocket, reason)

    async def dispatch_message(self, websocket: WebSocket, message_data: dict) -> None:
        with self._middleware_lock:
            middleware_snapshot = tuple(self._middleware)
        
        await self._execute_middleware_chain(EventType.MESSAGE, middleware_snapshot, websocket, message_data)
    
    @property
    def error_metrics(self) -> DispatcherErrorMetrics:
        return dispatcher_error_metrics
