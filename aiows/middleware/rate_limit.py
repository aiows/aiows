"""
Rate limiting middleware for aiows framework
"""

import time
from typing import Any, Awaitable, Callable, Dict, Optional
from .base import BaseMiddleware
from ..websocket import WebSocket


class RateLimitingMiddleware(BaseMiddleware):
    """
    Rate limiting middleware that limits the number of messages per client per minute.
    
    Protects against spam and DDoS attacks by tracking message frequency
    and blocking clients that exceed the specified rate limit.
    """
    
    def __init__(self, max_messages_per_minute: int = 60):
        """Initialize RateLimitingMiddleware with rate limit
        
        Args:
            max_messages_per_minute: Maximum number of messages allowed per minute (default: 60)
        """
        self.max_messages_per_minute = max_messages_per_minute
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.window_duration = 60  # 1 minute in seconds
    
    def _get_client_id(self, websocket: WebSocket) -> str:
        """Get unique client identifier
        
        Args:
            websocket: WebSocket connection instance
            
        Returns:
            Client identifier string
        """
        # Try to use user_id from context if available
        user_id = websocket.context.get('user_id')
        if user_id:
            return f"user_{user_id}"
        
        # Fall back to websocket object id as connection identifier
        return f"conn_{id(websocket)}"
    
    def _cleanup_expired_clients(self) -> None:
        """Remove expired client records to prevent memory leaks"""
        current_time = time.time()
        expired_clients = []
        
        for client_id, client_data in self.clients.items():
            if current_time - client_data.get('reset_time', 0) > self.window_duration * 2:
                expired_clients.append(client_id)
        
        for client_id in expired_clients:
            del self.clients[client_id]
    
    def _is_rate_limited(self, client_id: str) -> bool:
        """Check if client has exceeded rate limit
        
        Args:
            client_id: Client identifier
            
        Returns:
            True if client is rate limited, False otherwise
        """
        current_time = time.time()
        
        # Get or create client record
        if client_id not in self.clients:
            self.clients[client_id] = {
                'count': 0,
                'reset_time': current_time
            }
        
        client_data = self.clients[client_id]
        
        # Check if we need to reset the window
        if current_time - client_data['reset_time'] >= self.window_duration:
            client_data['count'] = 0
            client_data['reset_time'] = current_time
        
        # Increment message count
        client_data['count'] += 1
        
        # Check if limit is exceeded
        return client_data['count'] > self.max_messages_per_minute
    
    def _get_remaining_messages(self, client_id: str) -> int:
        """Get remaining messages for client in current window
        
        Args:
            client_id: Client identifier
            
        Returns:
            Number of remaining messages
        """
        if client_id not in self.clients:
            return self.max_messages_per_minute
        
        client_data = self.clients[client_id]
        current_time = time.time()
        
        # If window has expired, return full limit
        if current_time - client_data['reset_time'] >= self.window_duration:
            return self.max_messages_per_minute
        
        return max(0, self.max_messages_per_minute - client_data['count'])
    
    def _get_window_reset_time(self, client_id: str) -> float:
        """Get time when current window resets for client
        
        Args:
            client_id: Client identifier
            
        Returns:
            Timestamp when window resets
        """
        if client_id not in self.clients:
            return time.time() + self.window_duration
        
        client_data = self.clients[client_id]
        return client_data['reset_time'] + self.window_duration
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket connection event.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Cleanup expired clients periodically
        self._cleanup_expired_clients()
        
        # Call next handler
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket message event with rate limiting.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Extract websocket from args
        if not args or not isinstance(args[0], WebSocket):
            return await handler(*args, **kwargs)
        
        websocket = args[0]
        client_id = self._get_client_id(websocket)
        
        # Check rate limit
        if self._is_rate_limited(client_id):
            # Get information about rate limit for the response
            reset_time = self._get_window_reset_time(client_id)
            remaining_time = int(reset_time - time.time())
            
            # Close connection with rate limit exceeded code
            await websocket.close(
                code=4429, 
                reason=f"Rate limit exceeded. Try again in {remaining_time} seconds"
            )
            return
        
        # Store rate limit info in context for potential use by handlers
        websocket.context['rate_limit'] = {
            'remaining_messages': self._get_remaining_messages(client_id),
            'reset_time': self._get_window_reset_time(client_id),
            'limit': self.max_messages_per_minute
        }
        
        # Call next handler
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket disconnect event and cleanup client data.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Extract websocket from args and cleanup its data
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            client_id = self._get_client_id(websocket)
            
            # For connection-based IDs (not user-based), remove immediately
            if client_id.startswith("conn_"):
                self.clients.pop(client_id, None)
        
        # Call next handler
        return await handler(*args, **kwargs) 