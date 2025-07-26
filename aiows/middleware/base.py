"""
Base middleware class for aiows framework
"""

from typing import Any, Awaitable, Callable


class BaseMiddleware:
    """
    Base middleware class that provides basic interface for handling
    WebSocket events: connect, message, and disconnect.
    
    All middleware classes should inherit from this base class and
    override the necessary methods.
    """
    
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
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket message event.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket disconnect event.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        return await handler(*args, **kwargs) 