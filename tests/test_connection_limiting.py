"""
Tests for ConnectionLimiterMiddleware
"""

import asyncio
import time
import pytest
from unittest.mock import AsyncMock, MagicMock
from typing import List, Optional

from aiows.middleware.connection_limiter import ConnectionLimiterMiddleware
from aiows.websocket import WebSocket


class MockWebSocket(WebSocket):
    """Mock WebSocket for testing"""
    
    def __init__(self, remote_ip: str = "127.0.0.1", headers: Optional[dict] = None):
        self.remote_ip = remote_ip
        self.headers = headers or {}
        self.context = {}
        self._is_closed = False
        self._close_code = None
        self._close_reason = None
        
        # Mock the underlying websocket with remote_address
        mock_websocket = MagicMock()
        mock_websocket.remote_address = (remote_ip, 12345)
        
        # Alternative paths for IP detection
        mock_websocket.request = MagicMock()
        mock_websocket.request.remote = (remote_ip, 12345)
        mock_websocket.host = remote_ip
        
        # Initialize parent class with mock websocket
        super().__init__(mock_websocket)
        
        # Override context after parent init
        self.context = {}
    
    async def close(self, code: int = 1000, reason: str = ""):
        """Mock close method"""
        self._is_closed = True
        self._close_code = code
        self._close_reason = reason


class TestConnectionLimiterMiddleware:
    """Test cases for ConnectionLimiterMiddleware"""
    
    @pytest.fixture
    def middleware(self):
        """Create middleware instance for testing"""
        return ConnectionLimiterMiddleware(
            max_connections_per_ip=3,
            max_connections_per_minute=10,
            sliding_window_size=60,
            whitelist_ips=["192.168.1.100"],
            cleanup_interval=300
        )
    
    @pytest.fixture
    def mock_handler(self):
        """Create mock handler"""
        handler = AsyncMock()
        handler.return_value = "handler_result"
        return handler
    
    def test_init_default_values(self):
        """Test middleware initialization with default values"""
        middleware = ConnectionLimiterMiddleware()
        
        assert middleware.max_connections_per_ip == 10
        assert middleware.max_connections_per_minute == 30
        assert middleware.sliding_window_size == 60
        assert middleware.whitelist_ips == set()
        assert middleware.cleanup_interval == 300
        assert middleware.active_connections == {}
        assert middleware.connection_attempts == {}
    
    def test_init_custom_values(self):
        """Test middleware initialization with custom values"""
        whitelist = ["10.0.0.1", "10.0.0.2"]
        middleware = ConnectionLimiterMiddleware(
            max_connections_per_ip=5,
            max_connections_per_minute=20,
            sliding_window_size=120,
            whitelist_ips=whitelist,
            cleanup_interval=600
        )
        
        assert middleware.max_connections_per_ip == 5
        assert middleware.max_connections_per_minute == 20
        assert middleware.sliding_window_size == 120
        assert middleware.whitelist_ips == set(whitelist)
        assert middleware.cleanup_interval == 600
    
    def test_get_client_ip(self, middleware):
        """Test IP extraction from WebSocket"""
        # Test with remote_address
        ws1 = MockWebSocket("192.168.1.50")
        ip1 = middleware._get_client_ip(ws1)
        assert ip1 == "192.168.1.50"
        
        # Test with different IP
        ws2 = MockWebSocket("10.0.0.1")
        ip2 = middleware._get_client_ip(ws2)
        assert ip2 == "10.0.0.1"
        
        # Test with malformed WebSocket
        ws3 = MockWebSocket()
        ws3._websocket.remote_address = None
        ws3._websocket.request.remote = None
        ws3._websocket.host = "fallback.ip"
        ip3 = middleware._get_client_ip(ws3)
        assert ip3 == "fallback.ip"
    
    def test_whitelist_functionality(self, middleware):
        """Test whitelist functionality"""
        # Test whitelisted IP
        assert middleware._is_whitelisted("192.168.1.100") is True
        
        # Test non-whitelisted IP
        assert middleware._is_whitelisted("192.168.1.101") is False
        
        # Test adding to whitelist
        middleware.add_to_whitelist("10.0.0.1")
        assert middleware._is_whitelisted("10.0.0.1") is True
        
        # Test removing from whitelist
        middleware.remove_from_whitelist("192.168.1.100")
        assert middleware._is_whitelisted("192.168.1.100") is False
    
    def test_connection_limit_tracking(self, middleware):
        """Test connection limit tracking"""
        ip = "192.168.1.50"
        
        # Initially should allow connections
        assert middleware._check_connection_limit(ip) is True
        
        # Add connections up to limit
        for i in range(3):
            middleware._add_active_connection(ip, i)
            
        # Should still allow (we're at the limit, not over)
        assert len(middleware.active_connections[ip]) == 3
        assert middleware._check_connection_limit(ip) is False
        
        # Remove one connection
        middleware._remove_active_connection(ip, 0)
        assert middleware._check_connection_limit(ip) is True
        assert len(middleware.active_connections[ip]) == 2
        
        # Remove all connections
        middleware._remove_active_connection(ip, 1)
        middleware._remove_active_connection(ip, 2)
        assert ip not in middleware.active_connections
    
    def test_rate_limit_sliding_window(self, middleware):
        """Test rate limiting with sliding window"""
        ip = "192.168.1.50"
        
        # Should initially allow connections
        assert middleware._check_rate_limit(ip) is True
        
        # Add connections up to limit
        for i in range(10):
            middleware._record_connection_attempt(ip)
            if i < 9:
                assert middleware._check_rate_limit(ip) is True
        
        # Should be at limit now
        assert middleware._check_rate_limit(ip) is False
        
        # Manually age out some attempts
        old_time = time.time() - 70  # Outside 60s window
        middleware.connection_attempts[ip][:5] = [old_time] * 5
        
        # Should allow connections again
        assert middleware._check_rate_limit(ip) is True
    
    def test_cleanup_expired_data(self, middleware):
        """Test cleanup of expired tracking data"""
        ip1 = "192.168.1.50"
        ip2 = "192.168.1.51"
        
        # Add some connection attempts
        current_time = time.time()
        old_time = current_time - 120  # Outside window
        
        middleware.connection_attempts[ip1] = [old_time, current_time]
        middleware.connection_attempts[ip2] = [old_time, old_time]
        middleware.active_connections[ip1] = {1, 2}
        middleware.active_connections[ip2] = set()  # Empty set
        
        # Force cleanup
        middleware.last_cleanup = 0
        middleware._cleanup_expired_data()
        
        # Check results
        assert len(middleware.connection_attempts[ip1]) == 1  # Only recent attempt remains
        assert ip2 not in middleware.connection_attempts  # All attempts were old
        assert ip1 in middleware.active_connections  # Has active connections
        assert ip2 not in middleware.active_connections  # Empty set removed
    
    @pytest.mark.asyncio
    async def test_on_connect_normal_flow(self, middleware, mock_handler):
        """Test normal connection flow"""
        ws = MockWebSocket("192.168.1.50")
        
        # Should allow connection
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws._is_closed
        assert ws.context['connection_limiter']['ip'] == "192.168.1.50"
        assert ws.context['connection_limiter']['bypassed'] is False
        
        # Check that connection is tracked
        assert "192.168.1.50" in middleware.active_connections
        assert len(middleware.active_connections["192.168.1.50"]) == 1
    
    @pytest.mark.asyncio
    async def test_on_connect_whitelisted_ip(self, middleware, mock_handler):
        """Test connection from whitelisted IP"""
        ws = MockWebSocket("192.168.1.100")  # Whitelisted IP
        
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws._is_closed
        assert ws.context['connection_limiter']['bypassed'] is True
        assert ws.context['connection_limiter']['reason'] == 'whitelisted'
    
    @pytest.mark.asyncio
    async def test_on_connect_unknown_ip(self, middleware, mock_handler):
        """Test connection with unknown IP"""
        ws = MockWebSocket()
        ws._websocket.remote_address = None
        ws._websocket.request.remote = None
        delattr(ws._websocket, 'host')  # Remove host attribute completely
        
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws._is_closed
        assert ws.context['connection_limiter']['ip'] == 'unknown'
        assert ws.context['connection_limiter']['bypassed'] is True
        assert ws.context['connection_limiter']['reason'] == 'ip_detection_failed'
    
    @pytest.mark.asyncio
    async def test_on_connect_connection_limit_exceeded(self, middleware, mock_handler):
        """Test connection when connection limit is exceeded"""
        ip = "192.168.1.50"
        
        # Fill up connection slots
        for i in range(3):
            middleware._add_active_connection(ip, i)
        
        ws = MockWebSocket(ip)
        result = await middleware.on_connect(mock_handler, ws)
        
        # Connection should be closed
        assert ws._is_closed
        assert ws._close_code == 4008
        assert "Too many concurrent connections" in ws._close_reason
        assert not mock_handler.called
        assert result is None
    
    @pytest.mark.asyncio
    async def test_on_connect_rate_limit_exceeded(self, middleware, mock_handler):
        """Test connection when rate limit is exceeded"""
        ip = "192.168.1.50"
        
        # Fill up rate limit slots
        for i in range(10):
            middleware._record_connection_attempt(ip)
        
        ws = MockWebSocket(ip)
        result = await middleware.on_connect(mock_handler, ws)
        
        # Connection should be closed
        assert ws._is_closed
        assert ws._close_code == 4008
        assert "Connection rate limit exceeded" in ws._close_reason
        assert not mock_handler.called
        assert result is None
    
    @pytest.mark.asyncio
    async def test_on_message_passthrough(self, middleware, mock_handler):
        """Test that on_message passes through without modification"""
        ws = MockWebSocket("192.168.1.50")
        message = {"type": "test", "data": "hello"}
        
        result = await middleware.on_message(mock_handler, ws, message)
        
        assert result == "handler_result"
        mock_handler.assert_called_with(ws, message)
    
    @pytest.mark.asyncio
    async def test_on_disconnect_cleanup(self, middleware, mock_handler):
        """Test cleanup on disconnect"""
        ws = MockWebSocket("192.168.1.50")
        
        # First connect to set up tracking
        await middleware.on_connect(mock_handler, ws)
        
        # Verify connection is tracked
        ip = "192.168.1.50"
        connection_id = id(ws)
        assert connection_id in middleware.active_connections[ip]
        
        # Now disconnect
        result = await middleware.on_disconnect(mock_handler, ws)
        
        assert result == "handler_result"
        # Connection should be removed from tracking
        assert ip not in middleware.active_connections
    
    def test_get_stats_for_ip(self, middleware):
        """Test getting statistics for an IP"""
        ip = "192.168.1.50"
        
        # Add some data
        middleware._add_active_connection(ip, 1)
        middleware._add_active_connection(ip, 2)
        middleware._record_connection_attempt(ip)
        middleware._record_connection_attempt(ip)
        
        stats = middleware._get_stats_for_ip(ip)
        
        assert stats['active_connections'] == 2
        assert stats['recent_attempts'] == 2
        assert stats['max_connections'] == 3
        assert stats['max_rate'] == 10
        assert stats['is_whitelisted'] is False
    
    def test_get_global_stats(self, middleware):
        """Test getting global statistics"""
        # Add some test data
        middleware._add_active_connection("192.168.1.50", 1)
        middleware._add_active_connection("192.168.1.50", 2)
        middleware._add_active_connection("192.168.1.51", 3)
        middleware._record_connection_attempt("192.168.1.50")
        middleware._record_connection_attempt("192.168.1.51")
        
        stats = middleware.get_global_stats()
        
        assert stats['total_active_connections'] == 3
        assert stats['tracked_ips'] == 2
        assert stats['total_recent_attempts'] == 2
        assert stats['whitelist_size'] == 1  # From fixture
        assert stats['max_connections_per_ip'] == 3
    
    def test_is_ip_blocked(self, middleware):
        """Test IP blocking status check"""
        # Test allowed IP
        result = middleware.is_ip_blocked("192.168.1.50")
        assert result['blocked'] is False
        assert result['reason'] == 'allowed'
        
        # Test whitelisted IP
        result = middleware.is_ip_blocked("192.168.1.100")
        assert result['blocked'] is False
        assert result['reason'] == 'whitelisted'
        
        # Test rate limited IP
        ip = "192.168.1.51"
        for i in range(10):
            middleware._record_connection_attempt(ip)
        
        result = middleware.is_ip_blocked(ip)
        assert result['blocked'] is True
        assert result['reason'] == 'rate_limit_exceeded'
        
        # Test connection limited IP
        ip = "192.168.1.52"
        for i in range(3):
            middleware._add_active_connection(ip, i)
        
        result = middleware.is_ip_blocked(ip)
        assert result['blocked'] is True
        assert result['reason'] == 'connection_limit_exceeded'
    
    @pytest.mark.asyncio
    async def test_memory_usage_control(self, middleware):
        """Test that memory usage stays under control with cleanup"""
        # Create many connections from different IPs
        for i in range(100):
            ip = f"192.168.1.{i}"
            middleware._record_connection_attempt(ip)
            if i < 50:
                middleware._add_active_connection(ip, i)
        
        # Simulate time passage and disconnect half the connections
        for i in range(25):
            ip = f"192.168.1.{i}"
            middleware._remove_active_connection(ip, i)
        
        # Force cleanup with expired data
        middleware.last_cleanup = 0
        old_time = time.time() - 120
        for ip in list(middleware.connection_attempts.keys())[:50]:
            middleware.connection_attempts[ip] = [old_time]
        
        middleware._cleanup_expired_data()
        
        # Verify cleanup worked
        remaining_attempts = sum(
            len(attempts) for attempts in middleware.connection_attempts.values()
        )
        assert remaining_attempts < 100  # Some should be cleaned up
        
        # Active connections should only contain IPs with actual connections
        total_active = sum(
            len(connections) for connections in middleware.active_connections.values()
        )
        assert total_active == 25  # Only the remaining connections
    
    @pytest.mark.asyncio
    async def test_legitimate_traffic_not_blocked(self, middleware):
        """Test that legitimate traffic patterns are not blocked"""
        # Simulate legitimate usage: gradual connections from different IPs
        legitimate_ips = [f"192.168.1.{i}" for i in range(50, 60)]
        mock_handler = AsyncMock(return_value="success")
        
        # Each IP makes reasonable number of connections
        for ip in legitimate_ips:
            for conn in range(2):  # 2 connections per IP, within limit
                ws = MockWebSocket(ip)
                result = await middleware.on_connect(mock_handler, ws)
                assert result == "success"
                assert not ws._is_closed
                
                # Small delay to avoid rate limiting
                await asyncio.sleep(0.1)
        
        # All connections should succeed
        assert mock_handler.call_count == len(legitimate_ips) * 2
    
    @pytest.mark.asyncio
    async def test_concurrent_connections_thread_safety(self, middleware):
        """Test thread safety with concurrent connections"""
        mock_handler = AsyncMock(return_value="success")
        
        async def connect_from_ip(ip: str, connection_count: int):
            tasks = []
            for i in range(connection_count):
                ws = MockWebSocket(ip)
                task = middleware.on_connect(mock_handler, ws)
                tasks.append(task)
            await asyncio.gather(*tasks)
        
        # Run concurrent connections from multiple IPs
        await asyncio.gather(
            connect_from_ip("192.168.1.60", 2),
            connect_from_ip("192.168.1.61", 2),
            connect_from_ip("192.168.1.62", 2),
        )
        
        # Verify state consistency
        total_connections = sum(
            len(connections) for connections in middleware.active_connections.values()
        )
        assert total_connections == 6  # 3 IPs * 2 connections each
    
    def test_sliding_window_accuracy(self, middleware):
        """Test sliding window accuracy over time"""
        ip = "192.168.1.70"
        start_time = time.time()
        
        # Record attempts with specific timestamps
        timestamps = [start_time + i * 10 for i in range(8)]  # 8 attempts over 70 seconds
        middleware.connection_attempts[ip] = timestamps
        
        # At this point, all attempts should be within window (assuming test runs quickly)
        assert middleware._check_rate_limit(ip) is True  # 8 < 10, so allowed
        
        # Simulate time passing beyond window for first few attempts
        current_time = start_time + 70
        with pytest.MonkeyPatch().context() as m:
            m.setattr(time, 'time', lambda: current_time)
            
            # Only attempts from last 60 seconds should count
            # timestamps[1:] should be in range (start_time + 10 to start_time + 70)
            remaining_in_window = len([t for t in timestamps if t > current_time - 60])
            
            # Should allow more connections since older ones aged out
            assert middleware._check_rate_limit(ip) is True


if __name__ == "__main__":
    pytest.main([__file__]) 