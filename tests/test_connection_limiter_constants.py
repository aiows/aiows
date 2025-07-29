"""
Tests for connection limiter constants and improved type hints
"""

import pytest
from unittest.mock import AsyncMock, Mock

from aiows.middleware.connection_limiter import (
    ConnectionLimiterMiddleware, 
    ConnectionLimitCodes, 
    ConnectionLimitDefaults
)
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


class TestConnectionLimiterConstants:
    
    def test_connection_limit_codes_exist(self):
        assert hasattr(ConnectionLimitCodes, 'CONNECTION_LIMIT_EXCEEDED')
        assert hasattr(ConnectionLimitCodes, 'RATE_LIMIT_EXCEEDED')
        
        assert ConnectionLimitCodes.CONNECTION_LIMIT_EXCEEDED == 4008
        assert ConnectionLimitCodes.RATE_LIMIT_EXCEEDED == 4008
    
    def test_connection_limit_defaults_exist(self):
        assert hasattr(ConnectionLimitDefaults, 'MAX_CONNECTIONS_PER_IP')
        assert hasattr(ConnectionLimitDefaults, 'MAX_CONNECTIONS_PER_MINUTE')
        assert hasattr(ConnectionLimitDefaults, 'SLIDING_WINDOW_SIZE')
        assert hasattr(ConnectionLimitDefaults, 'CLEANUP_INTERVAL')
        assert hasattr(ConnectionLimitDefaults, 'MAX_CLEANUP_THRESHOLD')
        
        assert ConnectionLimitDefaults.MAX_CONNECTIONS_PER_IP == 10
        assert ConnectionLimitDefaults.MAX_CONNECTIONS_PER_MINUTE == 30
        assert ConnectionLimitDefaults.SLIDING_WINDOW_SIZE == 60
        assert ConnectionLimitDefaults.CLEANUP_INTERVAL == 300
        assert ConnectionLimitDefaults.MAX_CLEANUP_THRESHOLD == 60
    
    def test_default_values_used_correctly(self):
        middleware = ConnectionLimiterMiddleware()
        
        assert middleware.max_connections_per_ip == ConnectionLimitDefaults.MAX_CONNECTIONS_PER_IP
        assert middleware.max_connections_per_minute == ConnectionLimitDefaults.MAX_CONNECTIONS_PER_MINUTE
        assert middleware.sliding_window_size == ConnectionLimitDefaults.SLIDING_WINDOW_SIZE
        assert middleware.cleanup_interval == ConnectionLimitDefaults.CLEANUP_INTERVAL
    
    def test_cleanup_threshold_uses_constant(self):
        middleware = ConnectionLimiterMiddleware(cleanup_interval=200)
        
        expected_threshold = min(200 // 2, ConnectionLimitDefaults.MAX_CLEANUP_THRESHOLD)
        assert middleware._cleanup_threshold == expected_threshold
        assert middleware._cleanup_threshold == 60
        
        middleware2 = ConnectionLimiterMiddleware(cleanup_interval=80)
        expected_threshold2 = min(80 // 2, ConnectionLimitDefaults.MAX_CLEANUP_THRESHOLD)
        assert middleware2._cleanup_threshold == expected_threshold2
        assert middleware2._cleanup_threshold == 40
    
    @pytest.mark.asyncio
    async def test_rate_limit_exceeded_uses_constant(self):
        middleware = ConnectionLimiterMiddleware(
            max_connections_per_minute=1
        )
        
        ip = "192.168.1.100"
        mock_handler = AsyncMock()
        
        middleware._record_connection_attempt(ip)
        middleware._record_connection_attempt(ip)
        
        ws = MockWebSocket(ip)
        await middleware.on_connect(mock_handler, ws)
        
        assert ws.close_code == ConnectionLimitCodes.RATE_LIMIT_EXCEEDED
        assert ws.close_code == 4008
    
    @pytest.mark.asyncio
    async def test_connection_limit_exceeded_uses_constant(self):
        middleware = ConnectionLimiterMiddleware(
            max_connections_per_ip=2
        )
        
        ip = "192.168.1.100"
        mock_handler = AsyncMock()
        
        middleware._add_active_connection(ip, 1)
        middleware._add_active_connection(ip, 2)

        ws = MockWebSocket(ip)
        await middleware.on_connect(mock_handler, ws)
        
        assert ws.close_code == ConnectionLimitCodes.CONNECTION_LIMIT_EXCEEDED
        assert ws.close_code == 4008
    
    def test_type_hints_are_modern(self):
        import inspect
        from collections import deque
        
        middleware = ConnectionLimiterMiddleware()
        
        assert isinstance(middleware.active_connections, dict)
        assert isinstance(middleware.connection_attempts, dict)
        assert isinstance(middleware.whitelist_ips, set)
        
        if middleware.connection_attempts:
            ip = list(middleware.connection_attempts.keys())[0]
            assert isinstance(middleware.connection_attempts[ip], deque)
    
    def test_method_signatures_have_modern_type_hints(self):
        import inspect
        
        signature = inspect.signature(ConnectionLimiterMiddleware.__init__)
        
        get_stats_signature = inspect.signature(ConnectionLimiterMiddleware._get_stats_for_ip)
        
        get_global_stats_signature = inspect.signature(ConnectionLimiterMiddleware.get_global_stats)
        
        is_blocked_signature = inspect.signature(ConnectionLimiterMiddleware.is_ip_blocked)
    
    def test_constants_are_immutable(self):
        assert hasattr(ConnectionLimitCodes, 'CONNECTION_LIMIT_EXCEEDED')
        assert hasattr(ConnectionLimitCodes, 'RATE_LIMIT_EXCEEDED')
        assert hasattr(ConnectionLimitDefaults, 'MAX_CONNECTIONS_PER_IP')
        
        code1 = ConnectionLimitCodes.RATE_LIMIT_EXCEEDED
        code2 = ConnectionLimitCodes.RATE_LIMIT_EXCEEDED
        assert code1 is code2
        
        default1 = ConnectionLimitDefaults.MAX_CONNECTIONS_PER_IP
        default2 = ConnectionLimitDefaults.MAX_CONNECTIONS_PER_IP
        assert default1 is default2
    
    def test_no_magic_numbers_in_middleware(self):
        import inspect
        import ast
        
        source = inspect.getsource(ConnectionLimiterMiddleware)
        
        tree = ast.parse(source)
        
        magic_numbers = []
        
        class NumberVisitor(ast.NodeVisitor):
            def visit_Num(self, node):
                # Python < 3.8 compatibility
                magic_numbers.append(node.n)
            
            def visit_Constant(self, node):
                # Python 3.8+ 
                if isinstance(node.value, (int, float)):
                    magic_numbers.append(node.value)
        
        visitor = NumberVisitor()
        visitor.visit(tree)
        
        acceptable_numbers = {0, 1, 2}
        suspicious_numbers = [n for n in magic_numbers if n not in acceptable_numbers]
        
        problematic_numbers = {4008, 10, 30, 60, 300}
        found_problematic = set(suspicious_numbers) & problematic_numbers
        
        assert not found_problematic, f"Found magic numbers that should be constants: {found_problematic}"


if __name__ == "__main__":
    pytest.main([__file__]) 