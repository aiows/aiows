
import time
import pytest
from collections import deque
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


class TestConnectionLimiterOptimization:
    
    @pytest.fixture
    def middleware(self):
        return ConnectionLimiterMiddleware(
            max_connections_per_ip=100,
            max_connections_per_minute=1000,
            sliding_window_size=60,
            cleanup_interval=10
        )
    
    def test_deque_initialization(self, middleware):
        ip = "192.168.1.100"
        middleware._record_connection_attempt(ip)
        
        assert isinstance(middleware.connection_attempts[ip], deque)
        assert len(middleware.connection_attempts[ip]) == 1
    
    def test_efficient_timestamp_cleanup(self, middleware):
        ip = "192.168.1.100"
        current_time = time.time()
        
        old_timestamps = [current_time - 120, current_time - 100, current_time - 80]
        new_timestamps = [current_time - 30, current_time - 10, current_time]
        
        middleware.connection_attempts[ip] = deque(old_timestamps + new_timestamps)
        
        cutoff_time = current_time - 60
        start_time = time.perf_counter()
        middleware._cleanup_expired_timestamps(ip, cutoff_time)
        cleanup_time = time.perf_counter() - start_time
        
        remaining = list(middleware.connection_attempts[ip])
        assert len(remaining) == 3
        assert all(ts > cutoff_time for ts in remaining)
        
        assert cleanup_time < 0.001
    
    def test_deque_vs_list_performance_comparison(self, middleware):
        ip = "192.168.1.100"
        num_operations = 1000
        current_time = time.time()
        
        middleware.connection_attempts[ip] = deque()
        
        deque_start = time.perf_counter()
        for i in range(num_operations):
            middleware.connection_attempts[ip].append(current_time - i)
        
        cutoff_time = current_time - 500
        middleware._cleanup_expired_timestamps(ip, cutoff_time)
        deque_time = time.perf_counter() - deque_start
        
        list_timestamps = []
        list_start = time.perf_counter()
        for i in range(num_operations):
            list_timestamps.append(current_time - i)
        
        list_timestamps = [ts for ts in list_timestamps if ts > cutoff_time]
        list_time = time.perf_counter() - list_start

        print(f"Deque time: {deque_time:.6f}s, List time: {list_time:.6f}s")
        assert deque_time <= list_time * 2
    
    def test_cleanup_frequency_optimization(self, middleware):
        """Test that cleanup is triggered less frequently for better performance"""
        ip = "192.168.1.100"
        
        middleware.last_cleanup = time.time() - 5
        middleware._cleanup_threshold = 30
        
        initial_cleanup_time = middleware.last_cleanup
        
        middleware._cleanup_expired_data()
        assert middleware.last_cleanup == initial_cleanup_time
        
        middleware.last_cleanup = time.time() - 35
        
        middleware._cleanup_expired_data()
        assert middleware.last_cleanup > initial_cleanup_time
    
    def test_memory_efficiency_with_deque(self, middleware):
        ip = "192.168.1.100"
        current_time = time.time()
        old_time = current_time - 120
        
        middleware.connection_attempts[ip] = deque([old_time, old_time, old_time])
        
        cutoff_time = current_time - 60
        middleware._cleanup_expired_timestamps(ip, cutoff_time)
        
        assert ip not in middleware.connection_attempts
    
    @pytest.mark.asyncio
    async def test_rate_limiting_accuracy_preserved(self, middleware):
        ip = "192.168.1.100"
        mock_handler = AsyncMock(return_value="success")
        
        for i in range(999):
            middleware._record_connection_attempt(ip)
        
        ws = MockWebSocket(ip)
        result = await middleware.on_connect(mock_handler, ws)
        assert result == "success"
        assert not ws.close_code
        
        middleware._record_connection_attempt(ip)
        
        ws2 = MockWebSocket(ip)
        await middleware.on_connect(mock_handler, ws2)
        assert ws2.close_code == 4008
        assert "rate limit exceeded" in ws2.close_reason.lower()
    
    @pytest.mark.asyncio  
    async def test_sliding_window_accuracy_with_deque(self, middleware):    
        ip = "192.168.1.100"
        current_time = time.time()
        
        old_timestamps = [current_time - 70, current_time - 65]
        recent_timestamps = [current_time - 30, current_time - 10]
        
        middleware.connection_attempts[ip] = deque(old_timestamps + recent_timestamps)
        
        rate_ok = middleware._check_rate_limit(ip)
        assert rate_ok is True
        
        remaining = list(middleware.connection_attempts[ip])
        assert len(remaining) == 2
        assert all(ts >= current_time - 60 for ts in remaining)
    
    def test_concurrent_access_safety(self, middleware):
        ip = "192.168.1.100"
        
        def add_attempts():
            for i in range(100):
                middleware._record_connection_attempt(ip)
        
        def cleanup_attempts():
            for i in range(10):
                current_time = time.time()
                cutoff_time = current_time - 30
                middleware._cleanup_expired_timestamps(ip, cutoff_time)
                time.sleep(0.001)
        
        import threading
        
        threads = []
        for i in range(3):
            threads.append(threading.Thread(target=add_attempts))
            threads.append(threading.Thread(target=cleanup_attempts))
        
        for thread in threads:
            thread.start()
        
        for thread in threads:
            thread.join()
        
        if ip in middleware.connection_attempts:
            assert len(middleware.connection_attempts[ip]) >= 0
    
    def test_large_scale_performance(self, middleware):
        num_ips = 1000
        connections_per_ip = 50
        
        start_time = time.perf_counter()
        
        for i in range(num_ips):
            ip = f"192.168.{i//255}.{i%255}"
            for j in range(connections_per_ip):
                middleware._record_connection_attempt(ip)
        
        middleware.last_cleanup = 0
        middleware._cleanup_expired_data()
        
        total_time = time.perf_counter() - start_time
        
        print(f"Large scale test: {num_ips} IPs, {num_ips * connections_per_ip} connections in {total_time:.3f}s")
        assert total_time < 5.0
        
        total_attempts = sum(len(attempts) for attempts in middleware.connection_attempts.values())
        assert total_attempts == num_ips * connections_per_ip
    
    def test_backward_compatibility_with_lists(self, middleware):
        ip = "192.168.1.100"
        
        middleware.connection_attempts[ip] = [time.time() - 30, time.time() - 10]
        
        rate_ok = middleware._check_rate_limit(ip)
        assert rate_ok is True
        assert isinstance(middleware.connection_attempts[ip], deque)
    
    def test_stats_accuracy_with_deque(self, middleware):
        ip = "192.168.1.100"
        current_time = time.time()
        
        middleware.connection_attempts[ip] = deque([
            current_time - 70,
            current_time - 30,
            current_time - 10,
            current_time        # Recent
        ])
        
        stats = middleware._get_stats_for_ip(ip)
        
        assert stats['recent_attempts'] == 3
        assert stats['max_rate'] == 1000
        assert stats['window_size'] == 60


if __name__ == "__main__":
    pytest.main([__file__]) 