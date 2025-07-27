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
        self.max_messages_per_minute = max_messages_per_minute
        self.clients: Dict[str, Dict[str, Any]] = {}
        self.window_duration = 60  # 1 minute in seconds
    
    def _get_client_id(self, websocket: WebSocket) -> str:
        user_id = websocket.context.get('user_id')
        if user_id:
            return f"user_{user_id}"
        
        return f"conn_{id(websocket)}"
    
    def _cleanup_expired_clients(self) -> None:
        current_time = time.time()
        expired_clients = []
        
        for client_id, client_data in self.clients.items():
            if current_time - client_data.get('reset_time', 0) > self.window_duration * 2:
                expired_clients.append(client_id)
        
        for client_id in expired_clients:
            del self.clients[client_id]
    
    def _is_rate_limited(self, client_id: str) -> bool:
        current_time = time.time()
        
        if client_id not in self.clients:
            self.clients[client_id] = {
                'count': 0,
                'reset_time': current_time
            }
        
        client_data = self.clients[client_id]
        
        if current_time - client_data['reset_time'] >= self.window_duration:
            client_data['count'] = 0
            client_data['reset_time'] = current_time
        
        client_data['count'] += 1
        
        return client_data['count'] > self.max_messages_per_minute
    
    def _get_remaining_messages(self, client_id: str) -> int:
        if client_id not in self.clients:
            return self.max_messages_per_minute
        
        client_data = self.clients[client_id]
        current_time = time.time()
        
        if current_time - client_data['reset_time'] >= self.window_duration:
            return self.max_messages_per_minute
        
        return max(0, self.max_messages_per_minute - client_data['count'])
    
    def _get_window_reset_time(self, client_id: str) -> float:
        if client_id not in self.clients:
            return time.time() + self.window_duration
        
        client_data = self.clients[client_id]
        return client_data['reset_time'] + self.window_duration
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        self._cleanup_expired_clients()
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        if not args or not isinstance(args[0], WebSocket):
            return await handler(*args, **kwargs)
        
        websocket = args[0]
        client_id = self._get_client_id(websocket)
        
        if self._is_rate_limited(client_id):
            reset_time = self._get_window_reset_time(client_id)
            remaining_time = int(reset_time - time.time())
            
            await websocket.close(
                code=4429, 
                reason=f"Rate limit exceeded. Try again in {remaining_time} seconds"
            )
            return
        
        websocket.context['rate_limit'] = {
            'remaining_messages': self._get_remaining_messages(client_id),
            'reset_time': self._get_window_reset_time(client_id),
            'limit': self.max_messages_per_minute
        }
        
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            client_id = self._get_client_id(websocket)
            
            if client_id.startswith("conn_"):
                self.clients.pop(client_id, None)
        
        return await handler(*args, **kwargs) 