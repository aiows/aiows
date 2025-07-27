"""
Router implementation for WebSocket events
"""

from typing import List, Callable, Optional, Any
from functools import wraps
from .middleware.base import BaseMiddleware


class Router:
    """Router for registering WebSocket event handlers"""
    
    def __init__(self):
        self._connect_handlers: List[Callable] = []
        self._disconnect_handlers: List[Callable] = []
        self._message_handlers: List[Any] = []
        self._sub_routers: List[Any] = []
        self._middleware: List[BaseMiddleware] = []
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        self._middleware.append(middleware)
    
    def connect(self):
        """Decorator for registering connection handlers"""
        def decorator(func: Callable) -> Callable:
            self._connect_handlers.append(func)
            return func
        return decorator
    
    def disconnect(self):
        """Decorator for registering disconnection handlers"""
        def decorator(func: Callable) -> Callable:
            self._disconnect_handlers.append(func)
            return func
        return decorator
    
    def message(self, message_type: Optional[str] = None):
        """Decorator for registering message handlers"""
        def decorator(func: Callable) -> Callable:
            handler_info = {
                'handler': func,
                'message_type': message_type
            }
            self._message_handlers.append(handler_info)
            return func
        return decorator
    
    def include_router(self, router: 'Router', prefix: str = "") -> None:
        """Include sub-router with optional prefix"""
        sub_router_info = {
            'router': router,
            'prefix': prefix
        }
        self._sub_routers.append(sub_router_info)
    
    def get_all_middleware(self) -> List[BaseMiddleware]:
        """Get all middleware including from sub-routers"""
        all_middleware = self._middleware.copy()
        
        for sub_router_info in self._sub_routers:
            sub_router = sub_router_info['router']
            all_middleware.extend(sub_router.get_all_middleware())
        
        return all_middleware 