"""
Connection limiting middleware for aiows framework
"""

from __future__ import annotations

import time
from collections import deque
from typing import Any, Awaitable, Callable, TYPE_CHECKING
from .base import BaseMiddleware
from ..websocket import WebSocket

if TYPE_CHECKING:
    from ..settings import ConnectionLimiterConfig

# WebSocket close codes for connection limiting
class ConnectionLimitCodes:
    """WebSocket close codes used by connection limiter middleware"""
    CONNECTION_LIMIT_EXCEEDED = 4008
    RATE_LIMIT_EXCEEDED = 4008


# Default configuration values
class ConnectionLimitDefaults:
    """Default configuration values for connection limiter middleware"""
    MAX_CONNECTIONS_PER_IP = 10
    MAX_CONNECTIONS_PER_MINUTE = 30
    SLIDING_WINDOW_SIZE = 60  # seconds
    CLEANUP_INTERVAL = 300  # seconds
    MAX_CLEANUP_THRESHOLD = 60  # seconds


class ConnectionLimiterMiddleware(BaseMiddleware):
    """
    Connection limiting middleware that protects against connection flooding attacks.
    
    Features:
    - Limits maximum concurrent connections per IP
    - Rate limits new connection attempts using sliding window
    - Supports whitelist for trusted IPs
    - Automatic cleanup of expired tracking data
    - Optimized with deque for O(1) timestamp operations
    """
    
    def __init__(
        self,
        max_connections_per_ip: int | None = None,
        max_connections_per_minute: int | None = None,
        sliding_window_size: int | None = None,
        whitelist_ips: list[str] | None = None,
        cleanup_interval: int | None = None,
        config: ConnectionLimiterConfig | None = None
    ):
        # Load configuration
        if config is not None:
            self.max_connections_per_ip = config.max_connections_per_ip
            self.max_connections_per_minute = config.max_connections_per_minute
            self.sliding_window_size = config.sliding_window_size
            self.whitelist_ips: set[str] = set(config.whitelist_ips or [])
            self.cleanup_interval = config.cleanup_interval
        else:
            # Use provided parameters or defaults for backward compatibility
            self.max_connections_per_ip = max_connections_per_ip or ConnectionLimitDefaults.MAX_CONNECTIONS_PER_IP
            self.max_connections_per_minute = max_connections_per_minute or ConnectionLimitDefaults.MAX_CONNECTIONS_PER_MINUTE
            self.sliding_window_size = sliding_window_size or ConnectionLimitDefaults.SLIDING_WINDOW_SIZE
            self.whitelist_ips: set[str] = set(whitelist_ips or [])
            self.cleanup_interval = cleanup_interval or ConnectionLimitDefaults.CLEANUP_INTERVAL
        
        self.active_connections: dict[str, set[int]] = {}
        # Optimized: Use deque instead of list for O(1) operations  
        self.connection_attempts: dict[str, deque[float]] = {}
        self.last_cleanup: float = time.time()
        # Trigger cleanup less frequently for better performance
        self._cleanup_threshold: int = min(self.cleanup_interval // 2, ConnectionLimitDefaults.MAX_CLEANUP_THRESHOLD)
    
    @classmethod
    def from_config(cls, config: ConnectionLimiterConfig) -> ConnectionLimiterMiddleware:
        """Create ConnectionLimiterMiddleware instance from ConnectionLimiterConfig
        
        Args:
            config: ConnectionLimiterConfig instance with configuration
            
        Returns:
            Configured ConnectionLimiterMiddleware instance
        """
        return cls(config=config)
    
    def _get_client_ip(self, websocket: WebSocket) -> str | None:
        try:
            if hasattr(websocket._websocket, 'remote_address'):
                remote = websocket._websocket.remote_address
                if remote and len(remote) >= 1:
                    return str(remote[0])
            
            if hasattr(websocket._websocket, 'request') and hasattr(websocket._websocket.request, 'remote'):
                remote = websocket._websocket.request.remote
                if remote and len(remote) >= 1:
                    return str(remote[0])
            
            if hasattr(websocket._websocket, 'host'):
                host = websocket._websocket.host
                if host:
                    return str(host)
        except Exception:
            pass
        
        return None
    
    def _is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist_ips
    
    def _cleanup_expired_timestamps(self, ip: str, cutoff_time: float) -> None:
        """Efficiently remove expired timestamps from deque using O(1) popleft operations"""
        if ip not in self.connection_attempts:
            return
            
        attempts = self.connection_attempts[ip]
        
        # Handle case where tests might set lists instead of deques
        if isinstance(attempts, list):
            # Convert list to deque for compatibility
            attempts = deque(attempts)
            self.connection_attempts[ip] = attempts
        
        # Remove expired timestamps from left side of deque - O(1) per removal
        while attempts and attempts[0] <= cutoff_time:
            attempts.popleft()
        
        # Remove empty deques to save memory
        if not attempts:
            del self.connection_attempts[ip]
    
    def _cleanup_expired_data(self) -> None:
        current_time = time.time()
        
        # Only cleanup when necessary - reduced frequency for better performance
        if current_time - self.last_cleanup < self._cleanup_threshold:
            return
        
        cutoff_time = current_time - self.sliding_window_size
        
        # Cleanup expired timestamps for all IPs
        for ip in list(self.connection_attempts.keys()):
            self._cleanup_expired_timestamps(ip, cutoff_time)
        
        # Cleanup empty active connections
        for ip in list(self.active_connections.keys()):
            if not self.active_connections[ip]:
                del self.active_connections[ip]
        
        self.last_cleanup = current_time
    
    def _check_connection_limit(self, ip: str) -> bool:
        if ip not in self.active_connections:
            return True
        
        return len(self.active_connections[ip]) < self.max_connections_per_ip
    
    def _check_rate_limit(self, ip: str) -> bool:
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        
        if ip not in self.connection_attempts:
            self.connection_attempts[ip] = deque()
        
        # Optimized: Clean expired timestamps only for this IP using O(1) operations
        self._cleanup_expired_timestamps(ip, cutoff_time)
        
        # Check if deque still exists after cleanup (might have been deleted if empty)
        recent_attempts = len(self.connection_attempts.get(ip, deque()))
        return recent_attempts < self.max_connections_per_minute
    
    def _record_connection_attempt(self, ip: str) -> None:
        current_time = time.time()
        
        if ip not in self.connection_attempts:
            self.connection_attempts[ip] = deque()
        
        # O(1) operation
        self.connection_attempts[ip].append(current_time)
    
    def _add_active_connection(self, ip: str, connection_id: int) -> None:
        if ip not in self.active_connections:
            self.active_connections[ip] = set()
        
        self.active_connections[ip].add(connection_id)
    
    def _remove_active_connection(self, ip: str, connection_id: int) -> None:
        if ip in self.active_connections:
            self.active_connections[ip].discard(connection_id)
            
            if not self.active_connections[ip]:
                del self.active_connections[ip]
    
    def _get_connection_id(self, websocket: WebSocket) -> int:
        return id(websocket)
    
    def _get_stats_for_ip(self, ip: str) -> dict[str, Any]:
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        
        recent_attempts = 0
        if ip in self.connection_attempts:
            attempts = self.connection_attempts[ip]
            # Handle case where tests might set lists instead of deques
            if isinstance(attempts, list):
                attempts = deque(attempts)
                self.connection_attempts[ip] = attempts
            
            # Optimized: Count only valid timestamps in deque
            recent_attempts = len([
                timestamp for timestamp in attempts
                if timestamp > cutoff_time
            ])
        
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
        self._cleanup_expired_data()
        
        if not args or not isinstance(args[0], WebSocket):
            return await handler(*args, **kwargs)
        
        websocket = args[0]
        client_ip = self._get_client_ip(websocket)
        
        if not client_ip:
            websocket.context['connection_limiter'] = {
                'ip': 'unknown',
                'bypassed': True,
                'reason': 'ip_detection_failed'
            }
            return await handler(*args, **kwargs)
        
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
        
        if not self._check_rate_limit(client_ip):
            stats = self._get_stats_for_ip(client_ip)
            await websocket.close(
                code=ConnectionLimitCodes.RATE_LIMIT_EXCEEDED,
                reason=f"Connection rate limit exceeded. Max {self.max_connections_per_minute} connections per {self.sliding_window_size}s"
            )
            return
        
        if not self._check_connection_limit(client_ip):
            stats = self._get_stats_for_ip(client_ip)
            await websocket.close(
                code=ConnectionLimitCodes.CONNECTION_LIMIT_EXCEEDED,
                reason=f"Too many concurrent connections. Max {self.max_connections_per_ip} connections per IP"
            )
            return
        
        self._record_connection_attempt(client_ip)
        connection_id = self._get_connection_id(websocket)
        self._add_active_connection(client_ip, connection_id)
        
        websocket.context['connection_limiter'] = {
            'ip': client_ip,
            'bypassed': False,
            'connection_id': connection_id,
            'stats': self._get_stats_for_ip(client_ip)
        }
        
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        return await handler(*args, **kwargs)
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            
            limiter_info = websocket.context.get('connection_limiter', {})
            client_ip = limiter_info.get('ip')
            connection_id = limiter_info.get('connection_id')
            
            if client_ip and connection_id is not None:
                self._remove_active_connection(client_ip, connection_id)
        
        return await handler(*args, **kwargs)
    
    def get_global_stats(self) -> dict[str, Any]:
        total_active_connections = sum(
            len(connections) for connections in self.active_connections.values()
        )
        
        total_tracked_ips = len(self.active_connections)
        
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        total_recent_attempts = 0
        
        # Optimized: Count valid timestamps in deques
        for ip, attempts in list(self.connection_attempts.items()):
            # Handle case where tests might set lists instead of deques
            if isinstance(attempts, list):
                attempts = deque(attempts)
                self.connection_attempts[ip] = attempts
            
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
        self.whitelist_ips.add(ip)
    
    def remove_from_whitelist(self, ip: str) -> None:
        self.whitelist_ips.discard(ip)
    
    def is_ip_blocked(self, ip: str) -> dict[str, Any]:
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