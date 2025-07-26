"""
Authentication middleware for aiows framework
"""

from typing import Any, Awaitable, Callable, Optional
from urllib.parse import parse_qs, urlparse
from .base import BaseMiddleware
from ..websocket import WebSocket


class AuthMiddleware(BaseMiddleware):
    """
    Authentication middleware that validates tokens and manages user context.
    
    Validates tokens from headers or query parameters and adds user information
    to the WebSocket context. Closes connections with invalid tokens.
    """
    
    def __init__(self, secret_key: str):
        """Initialize AuthMiddleware with secret key
        
        Args:
            secret_key: Secret key for token validation
        """
        self.secret_key = secret_key
    
    def _extract_token(self, websocket: WebSocket) -> Optional[str]:
        """Extract token from headers or query parameters
        
        Args:
            websocket: WebSocket connection instance
            
        Returns:
            Token string if found, None otherwise
        """
        try:
            # Try to get token from authorization header
            if hasattr(websocket._websocket, 'request_headers'):
                headers = websocket._websocket.request_headers
                auth_header = headers.get('authorization') or headers.get('Authorization')
                if auth_header:
                    # Remove 'Bearer ' prefix if present
                    if auth_header.startswith('Bearer '):
                        return auth_header[7:]
                    return auth_header
            
            # Try to get token from query parameters
            if hasattr(websocket._websocket, 'path'):
                parsed_url = urlparse(websocket._websocket.path)
                query_params = parse_qs(parsed_url.query)
                if 'token' in query_params:
                    return query_params['token'][0]
            
            return None
        except Exception:
            return None
    
    def _validate_token(self, token: str) -> Optional[str]:
        """Validate token and extract user_id
        
        Args:
            token: Token to validate
            
        Returns:
            User ID if token is valid, None otherwise
        """
        if not token or self.secret_key not in token:
            return None
        
        # Simple validation: token should contain secret_key
        # Extract user_id (part before secret_key)
        try:
            parts = token.split(self.secret_key)
            if len(parts) >= 2 and parts[0]:
                return parts[0]
        except Exception:
            pass
        
        return None
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket connection event with authentication.
        
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
            
            # Extract and validate token
            token = self._extract_token(websocket)
            if not token:
                await websocket.close(code=4401, reason="Authentication required")
                return
            
            user_id = self._validate_token(token)
            if not user_id:
                await websocket.close(code=4401, reason="Invalid token")
                return
            
            # Store user_id in context
            websocket.context['user_id'] = user_id
            websocket.context['authenticated'] = True
        
        # Call next handler
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket message event with authentication check.
        
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
            
            # Check if user is authenticated
            if not websocket.context.get('authenticated') or not websocket.context.get('user_id'):
                await websocket.close(code=4401, reason="Authentication required")
                return
        
        # Call next handler
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
        # Standard processing - just call the handler
        return await handler(*args, **kwargs) 