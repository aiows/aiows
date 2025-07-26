"""
Router implementation for WebSocket events
"""

from typing import List, Callable, Optional, Any
from functools import wraps
from .middleware.base import BaseMiddleware


class Router:
    """Router for registering WebSocket event handlers"""
    
    def __init__(self):
        """Initialize Router with empty handler lists"""
        self._connect_handlers: List[Callable] = []
        self._disconnect_handlers: List[Callable] = []
        self._message_handlers: List[Any] = []
        self._sub_routers: List[Any] = []
        self._middleware: List[BaseMiddleware] = []
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        """Add middleware to the router
        
        Args:
            middleware: Middleware instance to add
        """
        self._middleware.append(middleware)
    
    def connect(self):
        """Decorator for registering connection handlers
        
        Returns:
            Decorator function that registers the handler
        """
        def decorator(func: Callable) -> Callable:
            self._connect_handlers.append(func)
            return func
        return decorator
    
    def disconnect(self):
        """Decorator for registering disconnection handlers
        
        Returns:
            Decorator function that registers the handler
        """
        def decorator(func: Callable) -> Callable:
            self._disconnect_handlers.append(func)
            return func
        return decorator
    
    def message(self, message_type: Optional[str] = None):
        """Decorator for registering message handlers
        
        Args:
            message_type: Optional message type to filter by
            
        Returns:
            Decorator function that registers the handler
        """
        def decorator(func: Callable) -> Callable:
            # Store handler with message type for later filtering
            handler_info = {
                'handler': func,
                'message_type': message_type
            }
            self._message_handlers.append(handler_info)
            return func
        return decorator
    
    def include_router(self, router: 'Router', prefix: str = "") -> None:
        """Include sub-router with optional prefix
        
        Args:
            router: Router instance to include
            prefix: Optional prefix for the sub-router
        """
        sub_router_info = {
            'router': router,
            'prefix': prefix
        }
        self._sub_routers.append(sub_router_info)
    
    def get_all_middleware(self) -> List[BaseMiddleware]:
        """Get all middleware including from sub-routers
        
        Returns:
            Combined list of middleware from this router and sub-routers
        """
        all_middleware = self._middleware.copy()
        
        # Add middleware from sub-routers
        for sub_router_info in self._sub_routers:
            sub_router = sub_router_info['router']
            all_middleware.extend(sub_router.get_all_middleware())
        
        return all_middleware 