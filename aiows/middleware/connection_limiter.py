"""
Connection limiting middleware for aiows framework
"""

import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set
from .base import BaseMiddleware
from ..websocket import WebSocket


class ConnectionLimiterMiddleware(BaseMiddleware):
    """
    Connection limiting middleware that protects against connection flooding attacks.
    
    Features:
    - Limits maximum concurrent connections per IP
    - Rate limits new connection attempts using sliding window
    - Supports whitelist for trusted IPs
    - Automatic cleanup of expired tracking data
    """
    
    def __init__(
        self,
        max_connections_per_ip: int = 10,
        max_connections_per_minute: int = 30,
        sliding_window_size: int = 60,
        whitelist_ips: Optional[List[str]] = None,
        cleanup_interval: int = 300  # 5 minutes
    ):
        """Initialize ConnectionLimiterMiddleware
        
        Args:
            max_connections_per_ip: Maximum concurrent connections per IP (default: 10)
            max_connections_per_minute: Maximum new connections per minute per IP (default: 30)
            sliding_window_size: Size of sliding window in seconds (default: 60)
            whitelist_ips: List of trusted IPs that bypass all limits (default: None)
            cleanup_interval: Interval for cleanup of expired data in seconds (default: 300)
        """
        self.max_connections_per_ip = max_connections_per_ip
        self.max_connections_per_minute = max_connections_per_minute
        self.sliding_window_size = sliding_window_size
        self.whitelist_ips: Set[str] = set(whitelist_ips or [])
        self.cleanup_interval = cleanup_interval
        
        # Track active connections per IP
        self.active_connections: Dict[str, Set[int]] = {}
        
        # Track connection attempts for rate limiting (sliding window)
        self.connection_attempts: Dict[str, List[float]] = {}
        
        # Track last cleanup time
        self.last_cleanup = time.time()
    
    def _get_client_ip(self, websocket: WebSocket) -> Optional[str]:
        """Extract client IP address from WebSocket connection
        
        Args:
            websocket: WebSocket connection instance
            
        Returns:
            Client IP address string or None if not available
        """
        try:
            # Try to get remote address from websocket
            if hasattr(websocket._websocket, 'remote_address'):
                remote = websocket._websocket.remote_address
                if remote and len(remote) >= 1:
                    return str(remote[0])
            
            # Try alternative methods
            if hasattr(websocket._websocket, 'request') and hasattr(websocket._websocket.request, 'remote'):
                remote = websocket._websocket.request.remote
                if remote and len(remote) >= 1:
                    return str(remote[0])
            
            # Fallback to host attribute if available
            if hasattr(websocket._websocket, 'host'):
                host = websocket._websocket.host
                if host:
                    return str(host)
        except Exception:
            pass
        
        return None
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist
        
        Args:
            ip: IP address to check
            
        Returns:
            True if IP is whitelisted, False otherwise
        """
        return ip in self.whitelist_ips
    
    def _cleanup_expired_data(self) -> None:
        """Remove expired connection tracking data to prevent memory leaks"""
        current_time = time.time()
        
        # Skip cleanup if not enough time has passed
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        # Clean up connection attempts older than sliding window
        cutoff_time = current_time - self.sliding_window_size
        for ip in list(self.connection_attempts.keys()):
            attempts = self.connection_attempts[ip]
            # Keep only attempts within the sliding window
            self.connection_attempts[ip] = [
                timestamp for timestamp in attempts 
                if timestamp > cutoff_time
            ]
            
            # Remove empty entries
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
        
        # Clean up empty active connections entries
        for ip in list(self.active_connections.keys()):
            if not self.active_connections[ip]:
                del self.active_connections[ip]
        
        self.last_cleanup = current_time
    
    def _check_connection_limit(self, ip: str) -> bool:
        """Check if IP has exceeded concurrent connection limit
        
        Args:
            ip: IP address to check
            
        Returns:
            True if connection should be allowed, False if limit exceeded
        """
        if ip not in self.active_connections:
            return True
        
        return len(self.active_connections[ip]) < self.max_connections_per_ip
    
    def _check_rate_limit(self, ip: str) -> bool:
        """Check if IP has exceeded connection rate limit using sliding window
        
        Args:
            ip: IP address to check
            
        Returns:
            True if connection should be allowed, False if rate limited
        """
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        
        # Get or create attempts list for this IP
        if ip not in self.connection_attempts:
            self.connection_attempts[ip] = []
        
        attempts = self.connection_attempts[ip]
        
        # Remove expired attempts (outside sliding window)
        self.connection_attempts[ip] = [
            timestamp for timestamp in attempts 
            if timestamp > cutoff_time
        ]
        
        # Check if adding this attempt would exceed the limit
        recent_attempts = len(self.connection_attempts[ip])
        return recent_attempts < self.max_connections_per_minute
    
    def _record_connection_attempt(self, ip: str) -> None:
        """Record a new connection attempt for rate limiting
        
        Args:
            ip: IP address making the connection attempt
        """
        current_time = time.time()
        
        if ip not in self.connection_attempts:
            self.connection_attempts[ip] = []
        
        self.connection_attempts[ip].append(current_time)
    
    def _add_active_connection(self, ip: str, connection_id: int) -> None:
        """Add a connection to the active connections tracking
        
        Args:
            ip: IP address of the connection
            connection_id: Unique identifier for the connection
        """
        if ip not in self.active_connections:
            self.active_connections[ip] = set()
        
        self.active_connections[ip].add(connection_id)
    
    def _remove_active_connection(self, ip: str, connection_id: int) -> None:
        """Remove a connection from the active connections tracking
        
        Args:
            ip: IP address of the connection
            connection_id: Unique identifier for the connection
        """
        if ip in self.active_connections:
            self.active_connections[ip].discard(connection_id)
            
            # Clean up empty entries
            if not self.active_connections[ip]:
                del self.active_connections[ip]
    
    def _get_connection_id(self, websocket: WebSocket) -> int:
        """Get unique identifier for WebSocket connection
        
        Args:
            websocket: WebSocket connection instance
            
        Returns:
            Unique connection identifier
        """
        return id(websocket)
    
    def _get_stats_for_ip(self, ip: str) -> Dict[str, Any]:
        """Get connection statistics for an IP
        
        Args:
            ip: IP address to get stats for
            
        Returns:
            Dictionary containing connection statistics
        """
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        
        # Count recent attempts
        recent_attempts = 0
        if ip in self.connection_attempts:
            recent_attempts = len([
                timestamp for timestamp in self.connection_attempts[ip]
                if timestamp > cutoff_time
            ])
        
        # Count active connections
        active_count = len(self.active_connections.get(ip, set()))
        
        return {
            'active_connections': active_count,
            'recent_attempts': recent_attempts,
            'max_connections': self.max_connections_per_ip,
            'max_rate': self.max_connections_per_minute,
            'window_size': self.sliding_window_size,
            'is_whitelisted': self._is_whitelisted(ip)
        }
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket connection event with connection limiting.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Perform periodic cleanup
        self._cleanup_expired_data()
        
        # Extract websocket from args
        if not args or not isinstance(args[0], WebSocket):
            return await handler(*args, **kwargs)
        
        websocket = args[0]
        client_ip = self._get_client_ip(websocket)
        
        # If we can't determine IP, allow connection but log it
        if not client_ip:
            websocket.context['connection_limiter'] = {
                'ip': 'unknown',
                'bypassed': True,
                'reason': 'ip_detection_failed'
            }
            return await handler(*args, **kwargs)
        
        # Check if IP is whitelisted
        if self._is_whitelisted(client_ip):
            connection_id = self._get_connection_id(websocket)
            self._add_active_connection(client_ip, connection_id)
            
            websocket.context['connection_limiter'] = {
                'ip': client_ip,
                'bypassed': True,
                'reason': 'whitelisted',
                'connection_id': connection_id,
                'stats': self._get_stats_for_ip(client_ip)
            }
            return await handler(*args, **kwargs)
        
        # Check rate limit first (before recording attempt)
        if not self._check_rate_limit(client_ip):
            # Rate limit exceeded - close connection
            stats = self._get_stats_for_ip(client_ip)
            await websocket.close(
                code=4008,  # Policy Violation
                reason=f"Connection rate limit exceeded. Max {self.max_connections_per_minute} connections per {self.sliding_window_size}s"
            )
            return
        
        # Check concurrent connection limit
        if not self._check_connection_limit(client_ip):
            # Connection limit exceeded - close connection
            stats = self._get_stats_for_ip(client_ip)
            await websocket.close(
                code=4008,  # Policy Violation
                reason=f"Too many concurrent connections. Max {self.max_connections_per_ip} connections per IP"
            )
            return
        
        # Record the connection attempt and add to active connections
        self._record_connection_attempt(client_ip)
        connection_id = self._get_connection_id(websocket)
        self._add_active_connection(client_ip, connection_id)
        
        # Store connection info in context
        websocket.context['connection_limiter'] = {
            'ip': client_ip,
            'bypassed': False,
            'connection_id': connection_id,
            'stats': self._get_stats_for_ip(client_ip)
        }
        
        # Call next handler
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
        # No special handling needed for messages in connection limiter
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        """
        Handle WebSocket disconnect event and cleanup connection tracking.
        
        Args:
            handler: The next handler in the chain to be called
            *args: Positional arguments passed to the handler
            **kwargs: Keyword arguments passed to the handler
            
        Returns:
            Result of the handler execution
        """
        # Extract websocket from args and cleanup its tracking data
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            
            # Get connection info from context if available
            limiter_info = websocket.context.get('connection_limiter', {})
            client_ip = limiter_info.get('ip')
            connection_id = limiter_info.get('connection_id')
            
            # If we have both IP and connection ID, remove from tracking
            if client_ip and connection_id is not None:
                self._remove_active_connection(client_ip, connection_id)
        
        # Call next handler
        return await handler(*args, **kwargs)
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Get global connection statistics
        
        Returns:
            Dictionary containing global statistics
        """
        total_active_connections = sum(
            len(connections) for connections in self.active_connections.values()
        )
        
        total_tracked_ips = len(self.active_connections)
        
        # Count recent attempts across all IPs
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        total_recent_attempts = 0
        
        for attempts in self.connection_attempts.values():
            total_recent_attempts += len([
                timestamp for timestamp in attempts
                if timestamp > cutoff_time
            ])
        
        return {
            'total_active_connections': total_active_connections,
            'tracked_ips': total_tracked_ips,
            'total_recent_attempts': total_recent_attempts,
            'whitelist_size': len(self.whitelist_ips),
            'max_connections_per_ip': self.max_connections_per_ip,
            'max_connections_per_minute': self.max_connections_per_minute,
            'sliding_window_size': self.sliding_window_size
        }
    
    def add_to_whitelist(self, ip: str) -> None:
        """Add IP to whitelist
        
        Args:
            ip: IP address to add to whitelist
        """
        self.whitelist_ips.add(ip)
    
    def remove_from_whitelist(self, ip: str) -> None:
        """Remove IP from whitelist
        
        Args:
            ip: IP address to remove from whitelist
        """
        self.whitelist_ips.discard(ip)
    
    def is_ip_blocked(self, ip: str) -> Dict[str, Any]:
        """Check if IP would be blocked and why
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with blocking status and reason
        """
        if self._is_whitelisted(ip):
            return {
                'blocked': False,
                'reason': 'whitelisted',
                'stats': self._get_stats_for_ip(ip)
            }
        
        if not self._check_rate_limit(ip):
            return {
                'blocked': True,
                'reason': 'rate_limit_exceeded',
                'stats': self._get_stats_for_ip(ip)
            }
        
        if not self._check_connection_limit(ip):
            return {
                'blocked': True,
                'reason': 'connection_limit_exceeded',
                'stats': self._get_stats_for_ip(ip)
            }
        
        return {
            'blocked': False,
            'reason': 'allowed',
            'stats': self._get_stats_for_ip(ip)
        } 