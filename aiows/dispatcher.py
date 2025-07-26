"""
Event dispatcher implementation
"""

import logging
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
        self.logger = logging.getLogger("aiows.dispatcher")
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        """Add middleware to the dispatcher
        
        Args:
            middleware: Middleware instance to add
        """
        self._middleware.append(middleware)
    
    async def _handle_middleware_exception(
        self, 
        exception: Exception, 
        middleware: BaseMiddleware, 
        event_type: str, 
        websocket: Optional[WebSocket] = None
    ) -> bool:
        """Handle middleware exceptions with appropriate logging and recovery
        
        Args:
            exception: The exception that occurred
            middleware: The middleware that raised the exception
            event_type: Type of event being processed (connect, message, disconnect)
            websocket: WebSocket instance if available
            
        Returns:
            True if execution should continue, False if chain should be interrupted
        """
        middleware_name = middleware.__class__.__name__
        
        # Log the exception with context
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
            
        else:
            # Unexpected exceptions
            self.logger.exception(
                f"Unexpected error in {middleware_name} during {event_type}: {str(exception)}"
            )
            # For unexpected errors, continue but log full traceback
            return True
    
    async def _execute_connect_chain(self, websocket: WebSocket) -> None:
        """Execute the original connect logic
        
        Args:
            websocket: WebSocket connection instance
        """
        for handler in self.router._connect_handlers:
            try:
                await handler(websocket)
            except Exception as e:
                self.logger.error(f"Error in connect handler: {str(e)}")
    
    async def _execute_disconnect_chain(self, websocket: WebSocket, reason: str) -> None:
        """Execute the original disconnect logic
        
        Args:
            websocket: WebSocket connection instance
            reason: Disconnection reason
        """
        for handler in self.router._disconnect_handlers:
            try:
                await handler(websocket, reason)
            except Exception as e:
                self.logger.error(f"Error in disconnect handler: {str(e)}")
    
    async def _execute_message_chain(self, websocket: WebSocket, message_data: dict) -> None:
        """Execute the original message logic
        
        Args:
            websocket: WebSocket connection instance
            message_data: Raw message data as dictionary
        """
        try:
            # Create appropriate message type based on message_data type
            message_type = message_data.get('type')
            
            if message_type == 'chat':
                message = ChatMessage(**message_data)
            elif message_type == 'join_room':
                message = JoinRoomMessage(**message_data)
            elif message_type == 'game_action':
                message = GameActionMessage(**message_data)
            else:
                # Fall back to BaseMessage for unknown types
                message = BaseMessage(**message_data)
        except Exception as e:
            raise MessageValidationError(f"Failed to parse message: {str(e)}")
        
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
            except Exception as e:
                self.logger.error(f"Error in message handler: {str(e)}")
        else:
            self.logger.warning(f"No handler found for message type: {message_type}")
    
    async def dispatch_connect(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection event
        
        Args:
            websocket: WebSocket connection instance
        """
        # Build middleware chain with exception handling
        handler = self._execute_connect_chain
        
        # Apply middleware in reverse order with exception wrapping
        for middleware in reversed(self._middleware):
            current_handler = handler
            current_middleware = middleware
            
            async def wrapped_handler(ws, mw=current_middleware, h=current_handler):
                try:
                    return await mw.on_connect(h, ws)
                except Exception as e:
                    should_continue = await self._handle_middleware_exception(
                        e, mw, "connect", ws
                    )
                    if not should_continue:
                        # For critical errors, close connection and stop processing
                        if not ws.closed:
                            try:
                                await ws.close(code=1011, reason="Server error")
                            except Exception:
                                pass
                        return
                    # For non-critical errors, continue with original handler
                    return await h(ws)
            
            handler = wrapped_handler
        
        # Execute the chain
        await handler(websocket)
    
    async def dispatch_disconnect(self, websocket: WebSocket, reason: str) -> None:
        """Handle WebSocket disconnection event
        
        Args:
            websocket: WebSocket connection instance
            reason: Disconnection reason
        """
        # Build middleware chain with exception handling
        handler = self._execute_disconnect_chain
        
        # Apply middleware in reverse order with exception wrapping
        for middleware in reversed(self._middleware):
            current_handler = handler
            current_middleware = middleware
            
            async def wrapped_handler(ws, r, mw=current_middleware, h=current_handler):
                try:
                    return await mw.on_disconnect(h, ws, r)
                except Exception as e:
                    should_continue = await self._handle_middleware_exception(
                        e, mw, "disconnect", ws
                    )
                    if not should_continue:
                        # For critical errors, stop processing but don't close (already disconnecting)
                        return
                    # For non-critical errors, continue with original handler
                    return await h(ws, r)
            
            handler = wrapped_handler
        
        # Execute the chain
        await handler(websocket, reason)
    
    async def dispatch_message(self, websocket: WebSocket, message_data: dict) -> None:
        """Handle WebSocket message event
        
        Args:
            websocket: WebSocket connection instance
            message_data: Raw message data as dictionary
        """
        # Build middleware chain with exception handling
        handler = self._execute_message_chain
        
        # Apply middleware in reverse order with exception wrapping
        for middleware in reversed(self._middleware):
            current_handler = handler
            current_middleware = middleware
            
            async def wrapped_handler(ws, data, mw=current_middleware, h=current_handler):
                try:
                    return await mw.on_message(h, ws, data)
                except Exception as e:
                    should_continue = await self._handle_middleware_exception(
                        e, mw, "message", ws
                    )
                    if not should_continue:
                        # For critical errors in message processing, stop but don't close connection
                        # (unless it's already closed by the middleware)
                        return
                    # For non-critical errors, continue with original handler
                    return await h(ws, data)
            
            handler = wrapped_handler
        
        # Execute the chain
        await handler(websocket, message_data) 