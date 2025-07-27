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
        cleanup_interval: int = 300
    ):
        self.max_connections_per_ip = max_connections_per_ip
        self.max_connections_per_minute = max_connections_per_minute
        self.sliding_window_size = sliding_window_size
        self.whitelist_ips: Set[str] = set(whitelist_ips or [])
        self.cleanup_interval = cleanup_interval
        
        self.active_connections: Dict[str, Set[int]] = {}
        self.connection_attempts: Dict[str, List[float]] = {}
        self.last_cleanup = time.time()
    
    def _get_client_ip(self, websocket: WebSocket) -> Optional[str]:
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
    
    def _cleanup_expired_data(self) -> None:
        current_time = time.time()
        
        if current_time - self.last_cleanup < self.cleanup_interval:
            return
        
        cutoff_time = current_time - self.sliding_window_size
        for ip in list(self.connection_attempts.keys()):
            attempts = self.connection_attempts[ip]
            self.connection_attempts[ip] = [
                timestamp for timestamp in attempts 
                if timestamp > cutoff_time
            ]
            
            if not self.connection_attempts[ip]:
                del self.connection_attempts[ip]
        
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
            self.connection_attempts[ip] = []
        
        attempts = self.connection_attempts[ip]
        
        self.connection_attempts[ip] = [
            timestamp for timestamp in attempts 
            if timestamp > cutoff_time
        ]
        
        recent_attempts = len(self.connection_attempts[ip])
        return recent_attempts < self.max_connections_per_minute
    
    def _record_connection_attempt(self, ip: str) -> None:
        current_time = time.time()
        
        if ip not in self.connection_attempts:
            self.connection_attempts[ip] = []
        
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
    
    def _get_stats_for_ip(self, ip: str) -> Dict[str, Any]:
        current_time = time.time()
        cutoff_time = current_time - self.sliding_window_size
        
        recent_attempts = 0
        if ip in self.connection_attempts:
            recent_attempts = len([
                timestamp for timestamp in self.connection_attempts[ip]
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
                code=4008,
                reason=f"Connection rate limit exceeded. Max {self.max_connections_per_minute} connections per {self.sliding_window_size}s"
            )
            return
        
        if not self._check_connection_limit(client_ip):
            stats = self._get_stats_for_ip(client_ip)
            await websocket.close(
                code=4008,
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
    
    def get_global_stats(self) -> Dict[str, Any]:
        total_active_connections = sum(
            len(connections) for connections in self.active_connections.values()
        )
        
        total_tracked_ips = len(self.active_connections)
        
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
        self.whitelist_ips.add(ip)
    
    def remove_from_whitelist(self, ip: str) -> None:
        self.whitelist_ips.discard(ip)
    
    def is_ip_blocked(self, ip: str) -> Dict[str, Any]:
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