"""
Final integration tests for aiows framework with health monitoring
"""

import asyncio
import json
import time
import unittest
from http.client import HTTPConnection
from unittest.mock import Mock, patch

import aiows
from aiows import (
    WebSocketServer, Router, WebSocket, MessageDispatcher,
    BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage,
    AiowsException, ConnectionError, MessageValidationError,
    BaseMiddleware, AuthMiddleware, LoggingMiddleware, RateLimitingMiddleware, ConnectionLimiterMiddleware,
    HealthStatus, HealthCheck, HealthChecker, 
    ConnectionsHealthCheck, MiddlewareHealthCheck, MemoryHealthCheck, SystemHealthCheck,
    setup_health_checks, get_health_checker
)


class TestFrameworkImports(unittest.TestCase):
    """Test that all framework components can be imported correctly"""
    
    def test_version_consistency(self):
        """Test version is consistent across the framework"""
        self.assertEqual(aiows.__version__, "0.1.1")
    
    def test_all_components_importable(self):
        """Test all components in __all__ can be imported"""
        for component_name in aiows.__all__:
            component = getattr(aiows, component_name)
            self.assertIsNotNone(component)
            self.assertTrue(callable(component) or hasattr(component, '__class__'))
    
    def test_core_components(self):
        """Test core framework components"""
        self.assertTrue(issubclass(WebSocketServer, object))
        self.assertTrue(issubclass(Router, object))
        self.assertTrue(issubclass(WebSocket, object))
        self.assertTrue(issubclass(MessageDispatcher, object))
    
    def test_message_types(self):
        """Test message type hierarchy"""
        self.assertTrue(issubclass(ChatMessage, BaseMessage))
        self.assertTrue(issubclass(JoinRoomMessage, BaseMessage))
        self.assertTrue(issubclass(GameActionMessage, BaseMessage))
    
    def test_exceptions(self):
        """Test exception hierarchy"""
        self.assertTrue(issubclass(AiowsException, Exception))
        self.assertTrue(issubclass(ConnectionError, AiowsException))
        self.assertTrue(issubclass(MessageValidationError, AiowsException))
    
    def test_middleware_components(self):
        """Test middleware hierarchy"""
        self.assertTrue(issubclass(AuthMiddleware, BaseMiddleware))
        self.assertTrue(issubclass(LoggingMiddleware, BaseMiddleware))
        self.assertTrue(issubclass(RateLimitingMiddleware, BaseMiddleware))
        self.assertTrue(issubclass(ConnectionLimiterMiddleware, BaseMiddleware))
    
    def test_health_components(self):
        """Test health monitoring components"""
        self.assertTrue(issubclass(HealthChecker, object))
        self.assertTrue(issubclass(HealthCheck, object))
        self.assertTrue(issubclass(ConnectionsHealthCheck, HealthCheck))
        self.assertTrue(issubclass(MiddlewareHealthCheck, HealthCheck))
        self.assertTrue(issubclass(MemoryHealthCheck, HealthCheck))
        self.assertTrue(issubclass(SystemHealthCheck, HealthCheck))
        
        self.assertEqual(HealthStatus.HEALTHY, "healthy")
        self.assertEqual(HealthStatus.DEGRADED, "degraded")
        self.assertEqual(HealthStatus.UNHEALTHY, "unhealthy")


class TestServerHealthIntegration(unittest.IsolatedAsyncioTestCase):
    """Test integration between WebSocket server and health monitoring"""
    
    def setUp(self):
        """Setup test environment"""
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        self.server = WebSocketServer()
        self.health_checker = setup_health_checks(
            self.server,
            http_port=9997,
            start_periodic=False,
            start_http=False
        )
    
    def tearDown(self):
        """Cleanup test environment"""
        if self.health_checker:
            self.health_checker.stop_http_endpoint()
    
    def test_server_with_health_monitoring(self):
        """Test server works with health monitoring enabled"""
        self.assertIsNotNone(self.health_checker)
        self.assertEqual(self.health_checker.server, self.server)
        
        self.assertIn("connections", self.health_checker.health_checks)
        self.assertIn("middleware", self.health_checker.health_checks)
        self.assertIn("memory", self.health_checker.health_checks)
        self.assertIn("system", self.health_checker.health_checks)
    
    async def test_health_checks_with_server_state(self):
        """Test health checks reflect actual server state"""
        results = await self.health_checker.run_all_checks()
        connections_result = results["connections"]
        self.assertEqual(connections_result.details["active_connections"], 0)
        
        middleware_result = results["middleware"]
        self.assertEqual(middleware_result.details["middleware_count"], 0)
    
    async def test_overall_health_status(self):
        """Test overall health status aggregation"""
        overall_health = await self.health_checker.get_overall_health()
        
        self.assertIn(overall_health.status, [HealthStatus.HEALTHY, HealthStatus.DEGRADED])
        self.assertIn("checks", overall_health.details)
        self.assertIn("performance", overall_health.details)
        self.assertEqual(overall_health.details["total_checks"], 4)
    
    def test_custom_health_check_integration(self):
        """Test custom health checks work with the framework"""
        async def custom_check():
            return HealthStatus(HealthStatus.HEALTHY, "Custom check OK")
        
        self.health_checker.register_custom_check("custom", custom_check)
        self.assertIn("custom", self.health_checker.custom_checks)
        
        self.health_checker.unregister_health_check("custom")
        self.assertNotIn("custom", self.health_checker.custom_checks)


class TestMiddlewareHealthIntegration(unittest.IsolatedAsyncioTestCase):
    """Test integration between middleware and health monitoring"""
    
    def setUp(self):
        """Setup test environment"""
        self.server = WebSocketServer()
        self.router = Router()
        self.server.include_router(self.router)
    
    def test_middleware_with_health_monitoring(self):
        """Test middleware integration with health checks"""
        auth_middleware = AuthMiddleware("this-is-a-very-long-secret-key-for-testing-purposes-32plus-chars")
        logging_middleware = LoggingMiddleware()
        
        self.server.add_middleware(auth_middleware)
        self.server.add_middleware(logging_middleware)
        
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        health_checker = setup_health_checks(
            self.server,
            start_periodic=False,
            start_http=False
        )
        
        try:
            self.assertEqual(len(self.server._middleware), 2)
            
            middleware_check = health_checker.health_checks["middleware"]
            self.assertIsInstance(middleware_check, MiddlewareHealthCheck)
        finally:
            health_checker.stop_http_endpoint()
    
    async def test_middleware_health_status(self):
        """Test middleware health status reporting"""
        class HealthAwareMiddleware(BaseMiddleware):
            def __init__(self, healthy=True):
                self.healthy = healthy
            
            async def health_check(self):
                return self.healthy
        
        unhealthy_middleware = HealthAwareMiddleware(False)
        
        self.server.add_middleware(unhealthy_middleware)
        
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        health_checker = setup_health_checks(
            self.server,
            start_periodic=False,
            start_http=False
        )
        
        try:
            results = await health_checker.run_all_checks()
            middleware_result = results["middleware"]
            
            self.assertEqual(middleware_result.status, HealthStatus.UNHEALTHY)
            self.assertIn("unhealthy_middleware", middleware_result.details)
        finally:
            health_checker.stop_http_endpoint()


class TestHTTPEndpointsIntegration(unittest.TestCase):
    """Test HTTP health endpoints integration"""
    
    def setUp(self):
        """Setup test environment"""
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        self.server = WebSocketServer()
        self.health_checker = setup_health_checks(
            self.server,
            http_port=9996,
            start_periodic=False,
            start_http=True
        )
        time.sleep(0.1)
    
    def tearDown(self):
        """Cleanup test environment"""
        self.health_checker.stop_http_endpoint()
    
    def test_http_endpoints_work(self):
        """Test all HTTP health endpoints work"""
        endpoints = [
            "/health",
            "/health/detailed", 
            "/health/performance",
            "/health/check/memory",
            "/health/check/system"
        ]
        
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                conn = HTTPConnection('localhost:9996')
                try:
                    conn.request('GET', endpoint)
                    response = conn.getresponse()
                    
                    self.assertIn(response.status, [200, 503])
                    
                    data = json.loads(response.read().decode())
                    self.assertIsInstance(data, dict)
                    
                finally:
                    conn.close()
    
    def test_health_endpoint_structure(self):
        """Test health endpoint returns proper structure"""
        conn = HTTPConnection('localhost:9996')
        try:
            conn.request('GET', '/health')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            required_fields = ["status", "message", "details", "timestamp"]
            for field in required_fields:
                self.assertIn(field, data)
            
            details = data["details"]
            self.assertIn("total_checks", details)
            self.assertIn("healthy", details)
            self.assertIn("degraded", details)
            self.assertIn("unhealthy", details)
            self.assertIn("checks", details)
            self.assertIn("performance", details)
            
        finally:
            conn.close()


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility is maintained"""
    
    def test_server_without_health_monitoring(self):
        """Test server works without health monitoring"""
        server = WebSocketServer()
        router = Router()
        server.include_router(router)
        
        self.assertIsNotNone(server)
        self.assertIsNotNone(router)
    
    def test_existing_api_unchanged(self):
        """Test existing API remains unchanged"""
        server = WebSocketServer()
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
            pass
        
        @router.message()
        async def handle_message(websocket: WebSocket, message: dict):
            pass
        
        @router.disconnect()
        async def handle_disconnect(websocket: WebSocket):
            pass
        
        server.include_router(router)
        
        self.assertTrue(len(router._connect_handlers) > 0)
        self.assertTrue(len(router._message_handlers) > 0)
        self.assertTrue(len(router._disconnect_handlers) > 0)
    
    def test_middleware_api_unchanged(self):
        """Test middleware API remains unchanged"""
        server = WebSocketServer()
        
        auth_middleware = AuthMiddleware("this-is-a-very-long-secret-key-for-testing-purposes-32plus-chars")
        logging_middleware = LoggingMiddleware()
        rate_limit_middleware = RateLimitingMiddleware()
        connection_limiter = ConnectionLimiterMiddleware()
        
        server.add_middleware(auth_middleware)
        server.add_middleware(logging_middleware)
        server.add_middleware(rate_limit_middleware)
        server.add_middleware(connection_limiter)
        
        self.assertEqual(len(server._middleware), 4)
    
    def test_message_types_unchanged(self):
        """Test message types API remains unchanged"""
        chat_msg = ChatMessage(text="Hello", user_id=123)
        join_msg = JoinRoomMessage(room_id="room1", user_name="testuser")
        game_msg = GameActionMessage(action="move", coordinates=(1, 2))
        
        self.assertEqual(chat_msg.text, "Hello")
        self.assertEqual(join_msg.room_id, "room1")
        self.assertEqual(join_msg.user_name, "testuser")
        self.assertEqual(game_msg.action, "move")
        self.assertEqual(game_msg.coordinates, (1, 2))


class TestFullStackIntegration(unittest.IsolatedAsyncioTestCase):
    """Test full stack integration with all components"""
    
    async def test_complete_framework_lifecycle(self):
        """Test complete framework lifecycle with health monitoring"""
        server = WebSocketServer()
        router = Router()
        
        logging_middleware = LoggingMiddleware()
        server.add_middleware(logging_middleware)
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
            websocket.context["connected"] = True
        
        @router.message()
        async def handle_message(websocket: WebSocket, message: dict):
            await websocket.send_json({"echo": message})
        
        @router.disconnect()
        async def handle_disconnect(websocket: WebSocket):
            pass
        
        server.include_router(router)
        
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        health_checker = setup_health_checks(
            server,
            http_port=9995,
            start_periodic=False,
            start_http=True
        )
        
        try:
            await asyncio.sleep(0.1)
            
            conn = HTTPConnection('localhost:9995')
            try:
                conn.request('GET', '/health')
                response = conn.getresponse()
                self.assertIn(response.status, [200, 503])
                
                data = json.loads(response.read().decode())
                self.assertIn("status", data)
                
            finally:
                conn.close()
            
            results = await health_checker.run_all_checks()
            self.assertGreater(len(results), 0)
            
            overall = await health_checker.get_overall_health()
            self.assertIsInstance(overall, HealthStatus)
            
        finally:
            health_checker.stop_http_endpoint()
    
    def test_framework_performance_with_monitoring(self):
        """Test framework performance impact of health monitoring is minimal"""
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        server = WebSocketServer()
        
        start_time = time.time()
        health_checker = setup_health_checks(
            server,
            start_periodic=False,
            start_http=False
        )
        setup_time = time.time() - start_time
        
        try:
            self.assertLess(setup_time, 1.0)
            
            start_time = time.time()
            asyncio.run(health_checker.run_all_checks())
            check_time = time.time() - start_time
            
            self.assertLess(check_time, 1.0)
            
        finally:
            health_checker.stop_http_endpoint()


class TestErrorHandlingIntegration(unittest.IsolatedAsyncioTestCase):
    """Test error handling across all components"""
    
    async def test_health_check_error_handling(self):
        """Test health check errors don't break the framework"""
        server = WebSocketServer()
        health_checker = HealthChecker(server)
        
        async def failing_check():
            raise Exception("Test failure")
        
        health_checker.register_custom_check("failing", failing_check)
        
        results = await health_checker.run_all_checks()
        self.assertIn("failing", results)
        self.assertEqual(results["failing"].status, HealthStatus.UNHEALTHY)
        self.assertIn("Test failure", results["failing"].message)
    
    def test_health_monitoring_with_server_errors(self):
        """Test health monitoring works even with server errors"""
        server = Mock()
        server._connection_count = None
        
        health_checker = HealthChecker(server)
        
        self.assertIsNotNone(health_checker)
        
        asyncio.run(self._check_handles_server_errors(health_checker))
    
    async def _check_handles_server_errors(self, health_checker):
        """Helper method to test server error handling"""
        results = await health_checker.run_all_checks()
        
        self.assertGreater(len(results), 0)
        
        self.assertIn("memory", results)
        self.assertIn("system", results)


if __name__ == '__main__':
    unittest.main() 