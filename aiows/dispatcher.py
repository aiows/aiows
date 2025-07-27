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
    
    async def execute_connect_chain(self, websocket: WebSocket) -> None:
        """Execute connect middleware chain"""
        return await self._execute_chain(
            "connect",
            self.dispatcher._execute_connect_chain,
            websocket
        )
    
    async def execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        """Execute disconnect middleware chain"""
        return await self._execute_chain(
            "disconnect", 
            self.dispatcher._execute_disconnect_chain,
            websocket,
            reason
        )
    
    async def execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        """Execute message middleware chain"""
        return await self._execute_chain(
            "message",
            self.dispatcher._execute_message_chain,
            websocket,
            message_data
        )
    
    async def _execute_chain(self, event_type: str, final_handler: Callable, *args) -> None:
        """Execute middleware chain without closures to prevent memory leaks"""
        
        # If no middleware, execute final handler directly
        if not self.middleware_list:
            return await final_handler(*args)
        
        # Create execution stack without closures
        # Middleware should execute in the order they were added (not reversed)
        stack = [(mw, event_type) for mw in self.middleware_list]
        stack.append((None, event_type))  # Final handler marker
        
        return await self._execute_middleware_stack(stack, final_handler, *args)
    
    async def _execute_middleware_stack(
        self, 
        stack: List, 
        final_handler: Callable, 
        *args
    ) -> None:
        """Execute middleware stack iteratively to avoid memory leaks"""
        
        if not stack:
            return
        
        current_middleware, event_type = stack.pop(0)
        
        if current_middleware is None:
            # Reached final handler
            return await final_handler(*args)
        
        try:
            # Create next handler for this middleware
            async def next_handler(*handler_args):
                return await self._execute_middleware_stack(stack, final_handler, *handler_args)
            
            # Execute middleware based on event type
            if event_type == "connect":
                return await current_middleware.on_connect(next_handler, *args)
            elif event_type == "disconnect":
                return await current_middleware.on_disconnect(next_handler, *args)
            elif event_type == "message":
                return await current_middleware.on_message(next_handler, *args)
            else:
                raise ValueError(f"Unknown event type: {event_type}")
                
        except Exception as e:
            # Get websocket from args for exception handling
            websocket = args[0] if args and hasattr(args[0], 'context') else None
            
            should_continue = await self.dispatcher._handle_middleware_exception(
                e, current_middleware, event_type, websocket
            )
            
            if not should_continue:
                # For critical errors, handle appropriately based on event type
                if event_type == "connect" and websocket and not websocket.closed:
                    try:
                        await websocket.close(code=1011, reason="Server error")
                    except Exception:
                        pass
                return
            
            # For non-critical errors, continue with remaining stack
            return await self._execute_middleware_stack(stack, final_handler, *args)


 