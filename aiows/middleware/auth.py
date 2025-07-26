"""
Secure authentication middleware for aiows framework with ticket-based authentication
"""

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from collections import defaultdict, deque, OrderedDict
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import parse_qs, urlparse
from .base import BaseMiddleware
from ..websocket import WebSocket

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Security-related error in authentication"""
    pass


class AuthenticationError(Exception):
    """Authentication failed error"""
    pass


class RateLimitError(Exception):
    """Rate limit exceeded error"""
    pass


class TicketManager:
    """Manages one-time use tickets for authentication with memory limits"""
    
    def __init__(self, cleanup_interval: int = 300, max_tickets: int = 50000):
        self._used_tickets: OrderedDict[str, float] = OrderedDict()
        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
        self.max_tickets = max_tickets
    
    def is_ticket_used(self, ticket_id: str) -> bool:
        """Check if ticket has already been used"""
        self._cleanup_expired()
        return ticket_id in self._used_tickets
    
    def mark_ticket_used(self, ticket_id: str) -> None:
        """Mark ticket as used with memory limits"""
        now = time.time()
        
        # Remove oldest tickets if we're at the limit
        while len(self._used_tickets) >= self.max_tickets:
            oldest_ticket = next(iter(self._used_tickets))
            del self._used_tickets[oldest_ticket]
            logger.debug(f"Removed oldest ticket {oldest_ticket} due to memory limit")
        
        self._used_tickets[ticket_id] = now
    
    def _cleanup_expired(self) -> None:
        """Clean up expired ticket records"""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return
        
        # Remove tickets older than 24 hours
        cutoff = now - 86400
        expired_tickets = [
            ticket_id for ticket_id, timestamp in self._used_tickets.items()
            if timestamp < cutoff
        ]
        
        for ticket_id in expired_tickets:
            del self._used_tickets[ticket_id]
        
        self._last_cleanup = now
        logger.debug(f"Cleaned up {len(expired_tickets)} expired tickets")


class RateLimiter:
    """Rate limiter for authentication attempts"""
    
    def __init__(self, max_attempts: int = 5, window_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, deque] = defaultdict(deque)
    
    def is_rate_limited(self, identifier: str) -> bool:
        """Check if identifier is rate limited"""
        now = time.time()
        attempts = self._attempts[identifier]
        
        # Remove old attempts outside the window
        while attempts and attempts[0] < now - self.window_seconds:
            attempts.popleft()
        
        return len(attempts) >= self.max_attempts
    
    def record_attempt(self, identifier: str) -> None:
        """Record an authentication attempt"""
        now = time.time()
        self._attempts[identifier].append(now)
        
        # Keep only recent attempts
        attempts = self._attempts[identifier]
        while attempts and attempts[0] < now - self.window_seconds:
            attempts.popleft()


class SecureToken:
    """Secure JWT-like token with HMAC-SHA256 signature"""
    
    @staticmethod
    def encode_payload(payload: dict) -> str:
        """Encode payload to URL-safe base64"""
        json_payload = json.dumps(payload, separators=(',', ':')).encode('utf-8')
        return base64.urlsafe_b64encode(json_payload).decode('ascii').rstrip('=')
    
    @staticmethod
    def decode_payload(encoded: str) -> dict:
        """Decode payload from URL-safe base64"""
        # Add padding if needed
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding
        
        json_payload = base64.urlsafe_b64decode(encoded.encode('ascii'))
        return json.loads(json_payload.decode('utf-8'))
    
    @staticmethod
    def create_signature(header: str, payload: str, secret: str) -> str:
        """Create HMAC-SHA256 signature"""
        message = f"{header}.{payload}".encode('utf-8')
        signature = hmac.new(secret.encode('utf-8'), message, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    
    @classmethod
    def generate(cls, user_id: str, secret_key: str, ttl_seconds: int = 300, 
                 client_ip: Optional[str] = None) -> str:
        """Generate a secure ticket token"""
        now = int(time.time())
        ticket_id = secrets.token_urlsafe(32)
        
        header = cls.encode_payload({
            "alg": "HS256",
            "typ": "JWT"
        })
        
        payload = cls.encode_payload({
            "sub": user_id,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": ticket_id,
            "ip": client_ip,
            "nonce": secrets.token_urlsafe(16)
        })
        
        signature = cls.create_signature(header, payload, secret_key)
        
        return f"{header}.{payload}.{signature}"
    
    @classmethod
    def verify(cls, token: str, secret_key: str, client_ip: Optional[str] = None) -> Dict[str, Any]:
        """Verify and decode token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise AuthenticationError("Invalid token format")
            
            header_encoded, payload_encoded, signature_encoded = parts
            
            # Verify signature
            expected_signature = cls.create_signature(header_encoded, payload_encoded, secret_key)
            if not hmac.compare_digest(signature_encoded, expected_signature):
                raise AuthenticationError("Invalid token signature")
            
            # Decode payload
            payload = cls.decode_payload(payload_encoded)
            
            # Check expiration
            now = int(time.time())
            if payload.get('exp', 0) < now:
                raise AuthenticationError("Token expired")
            
            # Check IP if provided
            if client_ip and payload.get('ip') and payload['ip'] != client_ip:
                raise SecurityError("IP address mismatch")
            
            return payload
            
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            raise AuthenticationError(f"Token decode error: {str(e)}")


class AuthMiddleware(BaseMiddleware):
    """
    Secure authentication middleware with ticket-based authentication.
    
    Features:
    - JWT-like tokens with HMAC-SHA256 signatures
    - One-time use tickets (replay protection)
    - Token expiration
    - IP address validation
    - Rate limiting for authentication attempts
    - Authentication via first WebSocket message
    """
    
    def __init__(self, 
                 secret_key: str,
                 token_ttl: int = 300,
                 enable_ip_validation: bool = True,
                 rate_limit_attempts: int = 5,
                 rate_limit_window: int = 300,
                 auth_timeout: int = 30,
                 max_tickets: int = 50000,
                 allowed_origins: Optional[List[str]] = None):
        """Initialize secure AuthMiddleware
        
        Args:
            secret_key: Secret key for token signing (should be cryptographically secure)
            token_ttl: Token time-to-live in seconds (default: 5 minutes)
            enable_ip_validation: Enable IP address validation (default: True)
            rate_limit_attempts: Max authentication attempts per window (default: 5)
            rate_limit_window: Rate limit window in seconds (default: 5 minutes)
            auth_timeout: Timeout for authentication in seconds (default: 30)
            max_tickets: Maximum number of tickets to keep in memory (default: 50000)
            allowed_origins: List of allowed origin headers (None = allow all)
        """
        if not secret_key or len(secret_key) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        
        self.secret_key = secret_key
        self.token_ttl = token_ttl
        self.enable_ip_validation = enable_ip_validation
        self.auth_timeout = auth_timeout
        self.allowed_origins = allowed_origins
        
        self.ticket_manager = TicketManager(max_tickets=max_tickets)
        self.rate_limiter = RateLimiter(rate_limit_attempts, rate_limit_window)
        
        # IP extraction strategies in order of preference
        self.ip_extractors = [
            self._extract_forwarded_ip,
            self._extract_real_ip,
            self._extract_remote_ip
        ]
        
        logger.info("Secure AuthMiddleware initialized")
    
    def _get_client_ip(self, websocket: WebSocket) -> Optional[str]:
        """Extract client IP address using configurable extractors"""
        for extractor in self.ip_extractors:
            try:
                ip = extractor(websocket)
                if ip:
                    return ip
            except Exception as e:
                logger.debug(f"IP extractor {extractor.__name__} failed: {e}")
                continue
        return None
    
    def _extract_forwarded_ip(self, websocket: WebSocket) -> Optional[str]:
        """Extract IP from X-Forwarded-For header"""
        headers = self._get_headers(websocket)
        forwarded = headers.get('x-forwarded-for')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return None
    
    def _extract_real_ip(self, websocket: WebSocket) -> Optional[str]:
        """Extract IP from X-Real-IP header"""
        headers = self._get_headers(websocket)
        return headers.get('x-real-ip')
    
    def _extract_remote_ip(self, websocket: WebSocket) -> Optional[str]:
        """Extract IP from remote address"""
        try:
            if hasattr(websocket._websocket, 'request') and websocket._websocket.request:
                request = websocket._websocket.request
                if hasattr(request, 'remote') and request.remote:
                    return str(request.remote[0])
            
            if hasattr(websocket._websocket, 'remote_address'):
                remote = websocket._websocket.remote_address
                return remote[0] if remote else None
        except Exception:
            pass
        return None
    
    def _get_headers(self, websocket: WebSocket) -> Dict[str, str]:
        """Extract headers from WebSocket connection"""
        try:
            if hasattr(websocket._websocket, 'request') and websocket._websocket.request:
                request = websocket._websocket.request
                if hasattr(request, 'headers') and request.headers:
                    return {k.lower(): v for k, v in request.headers.items()}
            return {}
        except Exception:
            return {}
    
    def _validate_security_headers(self, websocket: WebSocket) -> bool:
        """Validate security-related headers"""
        headers = self._get_headers(websocket)
        
        # Check Origin header if configured
        if self.allowed_origins is not None:
            origin = headers.get('origin')
            if not self._is_allowed_origin(origin):
                return False
        
        # Check User-Agent (basic bot detection)
        user_agent = headers.get('user-agent', '')
        if not user_agent or len(user_agent) < 10:
            logger.debug("Suspicious User-Agent header")
            return False  # Suspicious
        
        return True
    
    def _is_allowed_origin(self, origin: Optional[str]) -> bool:
        """Check if origin is in allowed list"""
        if not origin:
            return False
        
        if self.allowed_origins is None:
            return True  # Allow all if not configured
        
        return origin in self.allowed_origins
    
    def generate_token(self, user_id: str, client_ip: Optional[str] = None) -> str:
        """Generate a secure authentication token
        
        Args:
            user_id: User identifier
            client_ip: Client IP address for validation
            
        Returns:
            Secure JWT-like token
        """
        return SecureToken.generate(
            user_id=user_id,
            secret_key=self.secret_key,
            ttl_seconds=self.token_ttl,
            client_ip=client_ip if self.enable_ip_validation else None
        )
    
    async def _authenticate_via_message(self, websocket: WebSocket) -> bool:
        """Authenticate user via first WebSocket message
        
        Args:
            websocket: WebSocket connection
            
        Returns:
            True if authentication successful, False otherwise
        """
        client_ip = self._get_client_ip(websocket)
        rate_limit_key = client_ip or "unknown"
        
        try:
            # Check rate limit
            if self.rate_limiter.is_rate_limited(rate_limit_key):
                logger.warning(f"Rate limit exceeded for {rate_limit_key}")
                await websocket.close(code=4429, reason="Rate limit exceeded")
                return False
            
            # Validate security headers
            if not self._validate_security_headers(websocket):
                logger.warning(f"Security header validation failed for {rate_limit_key}")
                self.rate_limiter.record_attempt(rate_limit_key)
                await websocket.close(code=4403, reason="Security validation failed")
                return False
            
            # Wait for authentication message with timeout
            try:
                auth_message = await asyncio.wait_for(
                    websocket.recv(), 
                    timeout=self.auth_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(f"Authentication timeout for {rate_limit_key}")
                self.rate_limiter.record_attempt(rate_limit_key)
                await websocket.close(code=4401, reason="Authentication timeout")
                return False
            except (ConnectionResetError, ConnectionAbortedError):
                logger.info(f"Client {rate_limit_key} disconnected during auth")
                self.rate_limiter.record_attempt(rate_limit_key)
                return False
            except Exception as e:
                logger.error(f"Critical auth error from {rate_limit_key}: {e}")
                self.rate_limiter.record_attempt(rate_limit_key)
                await websocket.close(code=4500, reason="Internal authentication error")
                return False
            
            # Parse authentication message
            try:
                if isinstance(auth_message, str):
                    auth_data = json.loads(auth_message)
                else:
                    auth_data = auth_message
                
                if not isinstance(auth_data, dict) or 'token' not in auth_data:
                    raise ValueError("Invalid auth message format")
                
                token = auth_data['token']
                
            except (json.JSONDecodeError, ValueError) as e:
                logger.info(f"Invalid auth message format from {rate_limit_key}: {e}")
                self.rate_limiter.record_attempt(rate_limit_key)
                await websocket.close(code=4401, reason="Invalid authentication format")
                return False
            
            # Verify token
            try:
                payload = SecureToken.verify(
                    token=token,
                    secret_key=self.secret_key,
                    client_ip=client_ip if self.enable_ip_validation else None
                )
                
                ticket_id = payload.get('jti')
                if not ticket_id:
                    raise AuthenticationError("Missing ticket ID")
                
                # Check replay protection
                if self.ticket_manager.is_ticket_used(ticket_id):
                    raise SecurityError("Ticket already used (replay attack)")
                
                # Mark ticket as used
                self.ticket_manager.mark_ticket_used(ticket_id)
                
                # Store user info in context
                websocket.context['user_id'] = payload['sub']
                websocket.context['authenticated'] = True
                websocket.context['auth_timestamp'] = time.time()
                websocket.context['ticket_id'] = ticket_id
                
                logger.info(f"User {payload['sub']} authenticated successfully from {client_ip}")
                
                # Send authentication success response
                await websocket.send(json.dumps({
                    "type": "auth_success",
                    "user_id": payload['sub']
                }))
                
                return True
                
            except (AuthenticationError, SecurityError) as e:
                logger.warning(f"Authentication failed from {rate_limit_key}: {e}")
                self.rate_limiter.record_attempt(rate_limit_key)
                await websocket.close(code=4401, reason=str(e))
                return False
        
        except (ConnectionResetError, ConnectionAbortedError):
            logger.info(f"Client {rate_limit_key} disconnected during authentication")
            return False
        except asyncio.TimeoutError:
            logger.warning(f"Authentication process timeout for {rate_limit_key}")
            self.rate_limiter.record_attempt(rate_limit_key)
            await websocket.close(code=4401, reason="Authentication timeout")
            return False
        except Exception as e:
            logger.error(f"Critical authentication error from {rate_limit_key}: {e}")
            self.rate_limiter.record_attempt(rate_limit_key)
            await websocket.close(code=4500, reason="Internal authentication error")
            # Re-raise critical errors for debugging
            raise
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket connection with ticket-based authentication.
        
        Authentication happens via the first message after connection.
        """
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            
            # Perform authentication via first message
            auth_success = await self._authenticate_via_message(websocket)
            if not auth_success:
                return  # Connection closed due to auth failure
        
        # Call next handler only if authentication succeeded
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket message with authentication verification.
        
        All messages after authentication are allowed through.
        """
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            
            # Verify user is still authenticated
            if not websocket.context.get('authenticated') or not websocket.context.get('user_id'):
                logger.warning("Unauthenticated message attempt")
                await websocket.close(code=4401, reason="Authentication required")
                return
            
            # Optional: Check session timeout
            auth_time = websocket.context.get('auth_timestamp', 0)
            if time.time() - auth_time > 3600:  # 1 hour session timeout
                logger.info(f"Session expired for user {websocket.context.get('user_id')}")
                await websocket.close(code=4401, reason="Session expired")
                return
        
        # Call next handler
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket disconnect event.
        
        Clean up any authentication-related resources.
        """
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            user_id = websocket.context.get('user_id')
            if user_id:
                logger.info(f"User {user_id} disconnected")
        
        return await handler(*args, **kwargs)


# Utility functions for external use

def generate_auth_token(secret_key: str, user_id: str, client_ip: Optional[str] = None, 
                       ttl_seconds: int = 300) -> str:
    """Generate authentication token for external use
    
    Args:
        secret_key: Secret key for token signing
        user_id: User identifier  
        client_ip: Client IP address
        ttl_seconds: Token time-to-live in seconds
        
    Returns:
        Secure authentication token
    """
    return SecureToken.generate(user_id, secret_key, ttl_seconds, client_ip)


def verify_auth_token(token: str, secret_key: str, client_ip: Optional[str] = None) -> Dict[str, Any]:
    """Verify authentication token for external use
    
    Args:
        token: Token to verify
        secret_key: Secret key for verification
        client_ip: Client IP address
        
    Returns:
        Token payload if valid
        
    Raises:
        AuthenticationError: If token is invalid
        SecurityError: If security check fails
    """
    return SecureToken.verify(token, secret_key, client_ip) 