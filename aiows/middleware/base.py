"""
Base middleware class for aiows framework
"""

from typing import Any, Awaitable, Callable


class BaseMiddleware:
    """
    Base middleware class that provides basic interface for handling
    WebSocket events: connect, message, and disconnect.
    """
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        return await handler(*args, **kwargs)