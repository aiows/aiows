"""
Logging middleware for aiows framework
"""

import time
import json
import logging
from typing import Any, Awaitable, Callable, Optional
from .base import BaseMiddleware
from ..websocket import WebSocket


class LoggingMiddleware(BaseMiddleware):
    """
    Logging middleware that logs all WebSocket events: connections, messages, and disconnections.
    
    Provides structured logging for monitoring and debugging WebSocket interactions.
    """
    
    def __init__(self, logger_name: str = "aiows"):
        """Initialize LoggingMiddleware with logger name
        
        Args:
            logger_name: Name of the logger to use (default: "aiows")
        """
        self.logger = logging.getLogger(logger_name)
    
    def _get_client_info(self, websocket: WebSocket) -> dict:
        """Extract client information from WebSocket connection
        
        Args:
            websocket: WebSocket connection instance
            
        Returns:
            Dictionary with client information
        """
        client_info = {}
        
        try:
            # Try to get client IP address
            if hasattr(websocket._websocket, 'remote_address'):
                client_info['client_ip'] = str(websocket._websocket.remote_address[0])
            elif hasattr(websocket._websocket, 'host'):
                client_info['client_ip'] = websocket._websocket.host
        except Exception:
            client_info['client_ip'] = "unknown"
        
        # Get user ID from context if available
        user_id = websocket.context.get('user_id')
        if user_id:
            client_info['user_id'] = user_id
        
        # Get authentication status
        if websocket.context.get('authenticated'):
            client_info['authenticated'] = True
        
        return client_info
    
    def _get_message_info(self, message_data: dict) -> dict:
        """Extract message information
        
        Args:
            message_data: Raw message data
            
        Returns:
            Dictionary with message information
        """
        message_info = {}
        
        # Get message type
        message_info['message_type'] = message_data.get('type', 'unknown')
        
        # Calculate message size
        try:
            message_size = len(json.dumps(message_data))
            message_info['message_size'] = message_size
        except Exception:
            message_info['message_size'] = len(str(message_data))
        
        return message_info
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket connection event with logging.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Extract websocket from args (should be first argument)
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            client_info = self._get_client_info(websocket)
            
            self.logger.info(
                "WebSocket connection established - "
                f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                f"User ID: {client_info.get('user_id', 'anonymous')} - "
                f"Authenticated: {client_info.get('authenticated', False)}"
            )
        
        try:
            # Call next handler
            result = await handler(*args, **kwargs)
            return result
        except Exception as e:
            if args and isinstance(args[0], WebSocket):
                websocket = args[0]
                client_info = self._get_client_info(websocket)
                self.logger.error(
                    "Error during connection handling - "
                    f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                    f"Error: {str(e)}"
                )
            raise
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket message event with logging.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        start_time = time.time()
        
        # Extract websocket and message_data from args
        websocket = None
        message_data = None
        
        if len(args) >= 2 and isinstance(args[0], WebSocket):
            websocket = args[0]
            message_data = args[1]
        
        if websocket and message_data:
            client_info = self._get_client_info(websocket)
            message_info = self._get_message_info(message_data)
            
            self.logger.info(
                "Message received - "
                f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                f"User ID: {client_info.get('user_id', 'anonymous')} - "
                f"Message Type: {message_info.get('message_type', 'unknown')} - "
                f"Message Size: {message_info.get('message_size', 0)} bytes"
            )
        
        try:
            # Call next handler
            result = await handler(*args, **kwargs)
            
            # Log processing time
            processing_time = time.time() - start_time
            if websocket and message_data:
                client_info = self._get_client_info(websocket)
                message_info = self._get_message_info(message_data)
                
                self.logger.info(
                    "Message processed - "
                    f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                    f"User ID: {client_info.get('user_id', 'anonymous')} - "
                    f"Message Type: {message_info.get('message_type', 'unknown')} - "
                    f"Processing Time: {processing_time:.3f}s"
                )
            
            return result
        except Exception as e:
            processing_time = time.time() - start_time
            if websocket and message_data:
                client_info = self._get_client_info(websocket)
                message_info = self._get_message_info(message_data)
                
                self.logger.error(
                    "Error processing message - "
                    f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                    f"User ID: {client_info.get('user_id', 'anonymous')} - "
                    f"Message Type: {message_info.get('message_type', 'unknown')} - "
                    f"Processing Time: {processing_time:.3f}s - "
                    f"Error: {str(e)}"
                )
            raise
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket disconnect event with logging.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Extract websocket and reason from args
        websocket = None
        reason = "unknown"
        
        if len(args) >= 2 and isinstance(args[0], WebSocket):
            websocket = args[0]
            reason = str(args[1]) if args[1] else "unknown"
        
        if websocket:
            client_info = self._get_client_info(websocket)
            
            self.logger.info(
                "WebSocket connection closed - "
                f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                f"User ID: {client_info.get('user_id', 'anonymous')} - "
                f"Reason: {reason}"
            )
        
        try:
            # Call next handler
            result = await handler(*args, **kwargs)
            return result
        except Exception as e:
            if websocket:
                client_info = self._get_client_info(websocket)
                self.logger.error(
                    "Error during disconnection handling - "
                    f"Client IP: {client_info.get('client_ip', 'unknown')} - "
                    f"Error: {str(e)}"
                )
            raise 