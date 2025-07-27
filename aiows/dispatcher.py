"""
Event dispatcher implementation
"""

import asyncio
import copy
import logging
import threading
from .router import Router
from .websocket import WebSocket  
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage
from .exceptions import MessageValidationError, MiddlewareError, ConnectionError, AiowsException
from .middleware.base import BaseMiddleware
from typing import List, Callable, Any, Optional


class MessageDispatcher:
    """Dispatcher for handling WebSocket events and messages"""
    
    def __init__(self, router: Router):
        """Initialize MessageDispatcher with router
        
        Args:
            router: Router instance containing handlers
        """
        self.router = router
        self._middleware: List[BaseMiddleware] = []
        self._middleware_lock = threading.Lock()  # Thread safety for middleware list
        self.logger = logging.getLogger("aiows.dispatcher")
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        """Add middleware to the dispatcher in thread-safe manner
        
        Args:
            middleware: Middleware instance to add
        """
        with self._middleware_lock:
            self._middleware.append(middleware)
    
    def _parse_message_safely(self, message_data: dict) -> BaseMessage:
        """Parse message data safely with defensive copying
        
        Args:
            message_data: Raw message data dictionary
            
        Returns:
            Parsed BaseMessage instance
            
        Raises:
            MessageValidationError: If message parsing fails
        """
        try:
            # Create defensive copy to prevent race conditions
            safe_data = copy.deepcopy(message_data)
            message_type = safe_data.get('type')
            
            # Create appropriate message type based on message_data type
            if message_type == 'chat':
                return ChatMessage(**safe_data)
            elif message_type == 'join_room':
                return JoinRoomMessage(**safe_data)
            elif message_type == 'game_action':
                return GameActionMessage(**safe_data)
            else:
                # Fall back to BaseMessage for unknown types
                return BaseMessage(**safe_data)
                
        except (TypeError, ValueError, KeyError) as e:
            raise MessageValidationError(f"Failed to parse message: {str(e)}")
        except Exception as e:
            # Only catch specific parsing-related exceptions
            self.logger.error(f"Unexpected error during message parsing: {str(e)}")
            raise MessageValidationError(f"Message parsing failed: {str(e)}")
    
    async def _handle_middleware_exception(
        self, 
        exception: Exception, 
        middleware: BaseMiddleware, 
        event_type: str, 
        websocket: Optional[WebSocket] = None
    ) -> bool:
        """Handle middleware exceptions with selective exception handling
        
        Args:
            exception: The exception that occurred
            middleware: The middleware that raised the exception
            event_type: Type of event being processed (connect, message, disconnect)
            websocket: WebSocket instance if available
            
        Returns:
            True if execution should continue, False if chain should be interrupted
        """
        middleware_name = middleware.__class__.__name__
        
        # Handle specific framework exceptions first
        if isinstance(exception, MiddlewareError):
            self.logger.error(
                f"Middleware error in {middleware_name} during {event_type}: {str(exception)}"
            )
            # For middleware errors, check if it's critical (like auth failure)
            if "auth" in middleware_name.lower() or "security" in middleware_name.lower():
                self.logger.warning(f"Critical middleware {middleware_name} failed, interrupting chain")
                return False
            return True
            
        elif isinstance(exception, ConnectionError):
            self.logger.error(
                f"Connection error in {middleware_name} during {event_type}: {str(exception)}"
            )
            # Connection errors are usually critical
            return False
            
        elif isinstance(exception, MessageValidationError):
            self.logger.warning(
                f"Validation error in {middleware_name} during {event_type}: {str(exception)}"
            )
            # Validation errors should stop message processing but allow other middleware
            if event_type == "message":
                return False
            return True
            
        elif isinstance(exception, AiowsException):
            self.logger.error(
                f"Framework error in {middleware_name} during {event_type}: {str(exception)}"
            )
            return True
        
        # Handle specific standard library exceptions that should stop execution
        elif isinstance(exception, (asyncio.CancelledError, asyncio.TimeoutError)):
            self.logger.warning(
                f"Async operation cancelled/timed out in {middleware_name} during {event_type}: {str(exception)}"
            )
            return False
            
        elif isinstance(exception, (MemoryError, OSError)):
            self.logger.critical(
                f"System error in {middleware_name} during {event_type}: {str(exception)}"
            )
            return False
            
        else:
            # Only log unexpected exceptions, don't mask them with broad handling
            self.logger.exception(
                f"Unexpected error in {middleware_name} during {event_type}: {str(exception)}"
            )
            # Re-raise unexpected exceptions instead of silently continuing
            raise exception
    
    async def _execute_connect_chain(self, websocket: WebSocket) -> None:
        """Execute the original connect logic
        
        Args:
            websocket: WebSocket connection instance
        """
        for handler in self.router._connect_handlers:
            try:
                await handler(websocket)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                # Don't catch asyncio exceptions
                raise
            except Exception as e:
                self.logger.error(f"Error in connect handler: {str(e)}")
                # Don't re-raise handler exceptions to allow other handlers to run
    
    async def _execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        """Execute the original disconnect logic
        
        Args:
            websocket: WebSocket connection instance
            reason: Disconnection reason
        """
        for handler in self.router._disconnect_handlers:
            try:
                await handler(websocket, reason)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                # Don't catch asyncio exceptions
                raise
            except Exception as e:
                self.logger.error(f"Error in disconnect handler: {str(e)}")
                # Don't re-raise handler exceptions to allow other handlers to run
    
    async def _execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        """Execute the original message logic with safe parsing
        
        Args:
            websocket: WebSocket connection instance
            message_data: Raw message data as dictionary
        """
        # Parse message safely with defensive copying
        message = self._parse_message_safely(message_data)
        message_type = message.type
        
        # Find suitable handler by message type
        suitable_handler = None
        
        for handler_info in self.router._message_handlers:
            handler_message_type = handler_info.get('message_type')
            
            # Match by message type or universal handler (None)
            if handler_message_type is None or handler_message_type == message_type:
                suitable_handler = handler_info.get('handler')
                break
        
        # Call first found handler
        if suitable_handler:
            try:
                await suitable_handler(websocket, message)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                # Don't catch asyncio exceptions
                raise
            except Exception as e:
                self.logger.error(f"Error in message handler: {str(e)}")
                # Don't re-raise handler exceptions
        else:
            self.logger.warning(f"No handler found for message type: {message_type}")

    async def dispatch_connect(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection event
        
        Args:
            websocket: WebSocket connection instance
        """
        # Create thread-safe copy of middleware list
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        # Execute chain without memory leaks
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_connect_chain(websocket)

    async def dispatch_disconnect(self, websocket: WebSocket, reason: str) -> None:
        """Handle WebSocket disconnection event
        
        Args:
            websocket: WebSocket connection instance
            reason: Disconnection reason
        """
        # Create thread-safe copy of middleware list
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        # Execute chain without memory leaks  
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_disconnect_chain(websocket, reason)

    async def dispatch_message(self, websocket: WebSocket, message_data: dict) -> None:
        """Handle WebSocket message event
        
        Args:
            websocket: WebSocket connection instance
            message_data: Raw message data as dictionary
        """
        # Create thread-safe copy of middleware list
        with self._middleware_lock:
            middleware_copy = self._middleware.copy()
        
        # Execute chain without memory leaks
        executor = _MiddlewareChainExecutor(middleware_copy, self)
        await executor.execute_message_chain(websocket, message_data)


class _MiddlewareChainExecutor:
    """Helper class to execute middleware chains without memory leaks"""
    
    def __init__(self, middleware_list: List[BaseMiddleware], dispatcher: MessageDispatcher):
        self.middleware_list = middleware_list
        self.dispatcher = dispatcher
    
    def cleanup(self) -> None:
        """Explicit cleanup to prevent memory leaks"""
        self.middleware_list.clear()
        self.dispatcher = None
    
    async def execute_connect_chain(self, websocket: WebSocket) -> None:
        """Execute connect middleware chain without closures"""
        try:
            await self._execute_chain_iterative("connect", websocket)
        finally:
            self.cleanup()
    
    async def execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        """Execute disconnect middleware chain without closures"""
        try:
            await self._execute_chain_iterative("disconnect", websocket, reason)
        finally:
            self.cleanup()
    
    async def execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        """Execute message middleware chain without closures"""
        try:
            await self._execute_chain_iterative("message", websocket, message_data)
        finally:
            self.cleanup()
    
    async def _execute_chain_iterative(self, event_type: str, *args) -> None:
        """Execute middleware chain iteratively using stack without closures"""
        
        # If no middleware, execute final handler directly
        if not self.middleware_list:
            await self._execute_final_handler(event_type, *args)
            return
        
        # Create execution context that avoids closures
        context = _MiddlewareExecutionContext(
            self.middleware_list,
            self.dispatcher,
            event_type,
            args
        )
        
        # Start execution from the first middleware
        await context.execute_from_index(0)
    
    async def _execute_final_handler(self, event_type: str, *args) -> None:
        """Execute the final handler based on event type"""
        if event_type == "connect":
            await self.dispatcher._execute_connect_chain(*args)
        elif event_type == "disconnect":
            await self.dispatcher._execute_disconnect_chain(*args)
        elif event_type == "message":
            await self.dispatcher._execute_message_chain(*args)
        else:
            raise ValueError(f"Unknown event type: {event_type}")


class _MiddlewareExecutionContext:
    """Context for executing middleware without creating closures"""
    
    def __init__(self, middleware_list: List[BaseMiddleware], dispatcher: MessageDispatcher, event_type: str, args: tuple):
        self.middleware_list = middleware_list
        self.dispatcher = dispatcher
        self.event_type = event_type
        self.args = args
    
    async def execute_from_index(self, index: int) -> None:
        """Execute middleware chain starting from given index"""
        
        # If we've reached the end, execute final handler
        if index >= len(self.middleware_list):
            await self._execute_final_handler()
            return
        
        # Get current middleware
        current_middleware = self.middleware_list[index]
        
        try:
            # Create next handler for this specific index
            next_handler = _NextHandler(self, index + 1)
            
            # Execute middleware based on event type
            if self.event_type == "connect":
                await current_middleware.on_connect(next_handler.call, *self.args)
            elif self.event_type == "disconnect":
                await current_middleware.on_disconnect(next_handler.call, *self.args)
            elif self.event_type == "message":
                await current_middleware.on_message(next_handler.call, *self.args)
            else:
                raise ValueError(f"Unknown event type: {self.event_type}")
                
        except Exception as e:
            # Handle middleware exception
            websocket = self.args[0] if self.args and hasattr(self.args[0], 'context') else None
            
            should_continue = await self.dispatcher._handle_middleware_exception(
                e, current_middleware, self.event_type, websocket
            )
            
            if not should_continue:
                # For critical errors, handle appropriately
                if self.event_type == "connect" and websocket and not websocket.closed:
                    try:
                        await websocket.close(code=1011, reason="Server error")
                    except Exception:
                        pass
                return
            
            # For non-critical errors, continue with next middleware
            await self.execute_from_index(index + 1)
    
    async def _execute_final_handler(self) -> None:
        """Execute the final handler based on event type"""
        if self.event_type == "connect":
            await self.dispatcher._execute_connect_chain(*self.args)
        elif self.event_type == "disconnect":
            await self.dispatcher._execute_disconnect_chain(*self.args)
        elif self.event_type == "message":
            await self.dispatcher._execute_message_chain(*self.args)
        else:
            raise ValueError(f"Unknown event type: {self.event_type}")


class _NextHandler:
    """Next handler that avoids closures by storing context and index"""
    
    def __init__(self, context: _MiddlewareExecutionContext, next_index: int):
        self.context = context
        self.next_index = next_index
    
    async def call(self, *args) -> None:
        """Call the next middleware in the chain"""
        # Update args in context if they were modified
        if args:
            self.context.args = args
        
        # Continue execution from next index
        await self.context.execute_from_index(self.next_index)


 