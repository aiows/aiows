import asyncio
import time
import pytest
from unittest.mock import AsyncMock, Mock

from aiows.middleware.connection_limiter import ConnectionLimiterMiddleware
from aiows.websocket import WebSocket


class MockWebSocket(WebSocket):
    def __init__(self, remote_ip: str = "127.0.0.1"):
        mock_ws = Mock()
        mock_ws.remote_address = (remote_ip, 12345)
        super().__init__(mock_ws)
        
        self.send_data = []
        self.close_code = None
        self.close_reason = None
    
    async def close(self, code: int = 1000, reason: str = ""):
        await super().close(code, reason)
        self.close_code = code
        self.close_reason = reason


class TestConnectionLimiterMiddleware:
    
    @pytest.fixture
    def middleware(self):
        return ConnectionLimiterMiddleware(
            max_connections_per_ip=3,
            max_connections_per_minute=10,
            sliding_window_size=60,
            whitelist_ips=["192.168.1.100"],
            cleanup_interval=300
        )
    
    @pytest.fixture
    def mock_handler(self):
        handler = AsyncMock()
        handler.return_value = "handler_result"
        return handler
    
    def test_init_default_values(self):
        middleware = ConnectionLimiterMiddleware()
        
        assert middleware.max_connections_per_ip == 10
        assert middleware.max_connections_per_minute == 30
        assert middleware.sliding_window_size == 60
        assert middleware.whitelist_ips == set()
        assert middleware.cleanup_interval == 300
        assert middleware.active_connections == {}
        assert middleware.connection_attempts == {}
    
    def test_init_custom_values(self):
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
        ws1 = MockWebSocket("192.168.1.50")
        ip1 = middleware._get_client_ip(ws1)
        assert ip1 == "192.168.1.50"
        
        ws2 = MockWebSocket("10.0.0.1")
        ip2 = middleware._get_client_ip(ws2)
        assert ip2 == "10.0.0.1"
        
        ws3 = MockWebSocket()
        ws3._websocket.remote_address = None
        ws3._websocket.request.remote = None
        ws3._websocket.host = "fallback.ip"
        ip3 = middleware._get_client_ip(ws3)
        assert ip3 == "fallback.ip"
    
    def test_whitelist_functionality(self, middleware):
        assert middleware._is_whitelisted("192.168.1.100") is True
        assert middleware._is_whitelisted("192.168.1.101") is False
        
        middleware.add_to_whitelist("10.0.0.1")
        assert middleware._is_whitelisted("10.0.0.1") is True
        
        middleware.remove_from_whitelist("192.168.1.100")
        assert middleware._is_whitelisted("192.168.1.100") is False
    
    def test_connection_limit_tracking(self, middleware):
        ip = "192.168.1.50"
        
        assert middleware._check_connection_limit(ip) is True
        
        for i in range(3):
            middleware._add_active_connection(ip, i)
            
        assert len(middleware.active_connections[ip]) == 3
        assert middleware._check_connection_limit(ip) is False
        
        middleware._remove_active_connection(ip, 0)
        assert middleware._check_connection_limit(ip) is True
        assert len(middleware.active_connections[ip]) == 2
        
        middleware._remove_active_connection(ip, 1)
        middleware._remove_active_connection(ip, 2)
        assert ip not in middleware.active_connections
    
    def test_rate_limit_sliding_window(self, middleware):
        ip = "192.168.1.50"
        
        assert middleware._check_rate_limit(ip) is True
        
        for i in range(10):
            middleware._record_connection_attempt(ip)
            if i < 9:
                assert middleware._check_rate_limit(ip) is True
        
        assert middleware._check_rate_limit(ip) is False
        
        old_time = time.time() - 70
        attempts = middleware.connection_attempts[ip]
        new_attempts = [old_time] * 5 + list(attempts)[5:]
        middleware.connection_attempts[ip] = type(attempts)(new_attempts)
        
        assert middleware._check_rate_limit(ip) is True
    
    def test_cleanup_expired_data(self, middleware):
        ip1 = "192.168.1.50"
        ip2 = "192.168.1.51"
        
        current_time = time.time()
        old_time = current_time - 120
        
        middleware.connection_attempts[ip1] = [old_time, current_time]
        middleware.connection_attempts[ip2] = [old_time, old_time]
        middleware.active_connections[ip1] = {1, 2}
        middleware.active_connections[ip2] = set()
        
        middleware.last_cleanup = 0
        middleware._cleanup_expired_data()
        
        assert len(middleware.connection_attempts[ip1]) == 1
        assert ip2 not in middleware.connection_attempts
        assert ip1 in middleware.active_connections
        assert ip2 not in middleware.active_connections
    
    @pytest.mark.asyncio
    async def test_on_connect_normal_flow(self, middleware, mock_handler):
        ws = MockWebSocket("192.168.1.50")
        
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws.close_code
        assert ws.context['connection_limiter']['ip'] == "192.168.1.50"
        assert ws.context['connection_limiter']['bypassed'] is False
        
        assert "192.168.1.50" in middleware.active_connections
        assert len(middleware.active_connections["192.168.1.50"]) == 1
    
    @pytest.mark.asyncio
    async def test_on_connect_whitelisted_ip(self, middleware, mock_handler):
        ws = MockWebSocket("192.168.1.100")
        
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws.close_code
        assert ws.context['connection_limiter']['bypassed'] is True
        assert ws.context['connection_limiter']['reason'] == 'whitelisted'
    
    @pytest.mark.asyncio
    async def test_on_connect_unknown_ip(self, middleware, mock_handler):
        ws = MockWebSocket()
        ws._websocket.remote_address = None
        ws._websocket.request.remote = None
        delattr(ws._websocket, 'host')
        
        result = await middleware.on_connect(mock_handler, ws)
        
        assert result == "handler_result"
        assert mock_handler.called
        assert not ws.close_code
        assert ws.context['connection_limiter']['ip'] == 'unknown'
        assert ws.context['connection_limiter']['bypassed'] is True
        assert ws.context['connection_limiter']['reason'] == 'ip_detection_failed'
    
    @pytest.mark.asyncio
    async def test_on_connect_connection_limit_exceeded(self, middleware, mock_handler):
        ip = "192.168.1.50"
        
        for i in range(3):
            middleware._add_active_connection(ip, i)
        
        ws = MockWebSocket(ip)
        result = await middleware.on_connect(mock_handler, ws)
        
        assert ws.close_code == 4008
        assert "Too many concurrent connections" in ws.close_reason
        assert not mock_handler.called
        assert result is None
    
    @pytest.mark.asyncio
    async def test_on_connect_rate_limit_exceeded(self, middleware, mock_handler):
        ip = "192.168.1.50"
        
        for i in range(10):
            middleware._record_connection_attempt(ip)
        
        ws = MockWebSocket(ip)
        result = await middleware.on_connect(mock_handler, ws)
        
        assert ws.close_code == 4008
        assert "Connection rate limit exceeded" in ws.close_reason
        assert not mock_handler.called
        assert result is None
    
    @pytest.mark.asyncio
    async def test_on_message_passthrough(self, middleware, mock_handler):
        ws = MockWebSocket("192.168.1.50")
        message = {"type": "test", "data": "hello"}
        
        result = await middleware.on_message(mock_handler, ws, message)
        
        assert result == "handler_result"
        mock_handler.assert_called_with(ws, message)
    
    @pytest.mark.asyncio
    async def test_on_disconnect_cleanup(self, middleware, mock_handler):
        ws = MockWebSocket("192.168.1.50")
        
        await middleware.on_connect(mock_handler, ws)
        
        ip = "192.168.1.50"
        connection_id = id(ws)
        assert connection_id in middleware.active_connections[ip]
        
        result = await middleware.on_disconnect(mock_handler, ws)
        
        assert result == "handler_result"
        assert ip not in middleware.active_connections
    
    def test_get_stats_for_ip(self, middleware):
        ip = "192.168.1.50"
        
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
        middleware._add_active_connection("192.168.1.50", 1)
        middleware._add_active_connection("192.168.1.50", 2)
        middleware._add_active_connection("192.168.1.51", 3)
        middleware._record_connection_attempt("192.168.1.50")
        middleware._record_connection_attempt("192.168.1.51")
        
        stats = middleware.get_global_stats()
        
        assert stats['total_active_connections'] == 3
        assert stats['tracked_ips'] == 2
        assert stats['total_recent_attempts'] == 2
        assert stats['whitelist_size'] == 1
        assert stats['max_connections_per_ip'] == 3
    
    def test_is_ip_blocked(self, middleware):
        result = middleware.is_ip_blocked("192.168.1.50")
        assert result['blocked'] is False
        assert result['reason'] == 'allowed'
        
        result = middleware.is_ip_blocked("192.168.1.100")
        assert result['blocked'] is False
        assert result['reason'] == 'whitelisted'
        
        ip = "192.168.1.51"
        for i in range(10):
            middleware._record_connection_attempt(ip)
        
        result = middleware.is_ip_blocked(ip)
        assert result['blocked'] is True
        assert result['reason'] == 'rate_limit_exceeded'
        
        ip = "192.168.1.52"
        for i in range(3):
            middleware._add_active_connection(ip, i)
        
        result = middleware.is_ip_blocked(ip)
        assert result['blocked'] is True
        assert result['reason'] == 'connection_limit_exceeded'
    
    @pytest.mark.asyncio
    async def test_memory_usage_control(self, middleware):
        for i in range(100):
            ip = f"192.168.1.{i}"
            middleware._record_connection_attempt(ip)
            if i < 50:
                middleware._add_active_connection(ip, i)
        
        for i in range(25):
            ip = f"192.168.1.{i}"
            middleware._remove_active_connection(ip, i)
        
        middleware.last_cleanup = 0
        old_time = time.time() - 120
        for ip in list(middleware.connection_attempts.keys())[:50]:
            middleware.connection_attempts[ip] = [old_time]
        
        middleware._cleanup_expired_data()
        
        remaining_attempts = sum(
            len(attempts) for attempts in middleware.connection_attempts.values()
        )
        assert remaining_attempts < 100
        
        total_active = sum(
            len(connections) for connections in middleware.active_connections.values()
        )
        assert total_active == 25
    
    @pytest.mark.asyncio
    async def test_legitimate_traffic_not_blocked(self, middleware):
        legitimate_ips = [f"192.168.1.{i}" for i in range(50, 60)]
        mock_handler = AsyncMock(return_value="success")
        
        for ip in legitimate_ips:
            for conn in range(2):
                ws = MockWebSocket(ip)
                result = await middleware.on_connect(mock_handler, ws)
                assert result == "success"
                assert not ws.close_code
                
                await asyncio.sleep(0.1)
        
        assert mock_handler.call_count == len(legitimate_ips) * 2
    
    @pytest.mark.asyncio
    async def test_concurrent_connections_thread_safety(self, middleware):
        mock_handler = AsyncMock(return_value="success")
        
        async def connect_from_ip(ip: str, connection_count: int):
            tasks = []
            for i in range(connection_count):
                ws = MockWebSocket(ip)
                task = middleware.on_connect(mock_handler, ws)
                tasks.append(task)
            await asyncio.gather(*tasks)
        
        await asyncio.gather(
            connect_from_ip("192.168.1.60", 2),
            connect_from_ip("192.168.1.61", 2),
            connect_from_ip("192.168.1.62", 2),
        )
        
        total_connections = sum(
            len(connections) for connections in middleware.active_connections.values()
        )
        assert total_connections == 6
    
    def test_sliding_window_accuracy(self, middleware):
        ip = "192.168.1.70"
        start_time = time.time()
        
        timestamps = [start_time + i * 10 for i in range(8)]
        middleware.connection_attempts[ip] = timestamps
        
        assert middleware._check_rate_limit(ip) is True
        
        current_time = start_time + 70
        with pytest.MonkeyPatch().context() as m:
            m.setattr(time, 'time', lambda: current_time)
            remaining_in_window = len([t for t in timestamps if t > current_time - 60])
            assert middleware._check_rate_limit(ip) is True


if __name__ == "__main__":
    pytest.main([__file__]) 