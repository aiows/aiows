"""
Tests for aiows health check system
"""

import asyncio
import json
import time
import unittest
from datetime import datetime
from http.client import HTTPConnection
from unittest.mock import Mock, patch, AsyncMock
from aiows.health import (
    HealthStatus, HealthCheck, HealthChecker,
    ConnectionsHealthCheck, MiddlewareHealthCheck, 
    MemoryHealthCheck, SystemHealthCheck,
    setup_health_checks, get_health_checker
)


class MockWebSocketServer:
    """Mock WebSocket server for testing"""
    
    def __init__(self, connection_count=0, total_connections=0, middleware=None):
        self._connection_count = connection_count
        self._total_connections = total_connections
        self._middleware = middleware or []


class MockMiddleware:
    """Mock middleware for testing"""
    
    def __init__(self, health_status=True, should_raise=False):
        self.health_status = health_status
        self.should_raise = should_raise
    
    async def health_check(self):
        if self.should_raise:
            raise Exception("Middleware health check failed")
        return self.health_status


class TestHealthStatus(unittest.TestCase):
    def test_health_status_creation(self):
        status = HealthStatus(
            status=HealthStatus.HEALTHY,
            message="All good",
            details={"key": "value"}
        )
        
        self.assertEqual(status.status, HealthStatus.HEALTHY)
        self.assertEqual(status.message, "All good")
        self.assertEqual(status.details["key"], "value")
        self.assertIsInstance(status.timestamp, datetime)
        self.assertTrue(status.is_healthy())
    
    def test_health_status_to_dict(self):
        status = HealthStatus(
            status=HealthStatus.DEGRADED,
            message="Performance issues",
            details={"latency": 500}
        )
        
        result = status.to_dict()
        
        self.assertEqual(result["status"], HealthStatus.DEGRADED)
        self.assertEqual(result["message"], "Performance issues")
        self.assertEqual(result["details"]["latency"], 500)
        self.assertIn("timestamp", result)
    
    def test_health_status_types(self):
        healthy = HealthStatus(status=HealthStatus.HEALTHY)
        degraded = HealthStatus(status=HealthStatus.DEGRADED)
        unhealthy = HealthStatus(status=HealthStatus.UNHEALTHY)
        
        self.assertTrue(healthy.is_healthy())
        self.assertFalse(degraded.is_healthy())
        self.assertFalse(unhealthy.is_healthy())


class TestBaseHealthCheck(unittest.TestCase):
    def test_health_check_creation(self):
        check = HealthCheck("test_check", timeout=10.0)
        
        self.assertEqual(check.name, "test_check")
        self.assertEqual(check.timeout, 10.0)
        self.assertIsNone(check.last_result)
        self.assertIsNone(check.last_run)
    
    def test_health_check_not_implemented(self):
        check = HealthCheck("test")
        
        async def run_test():
            with self.assertRaises(NotImplementedError):
                await check.check()
        
        asyncio.run(run_test())
    
    def test_health_check_timeout(self):
        class SlowCheck(HealthCheck):
            async def check(self):
                await asyncio.sleep(2)
                return HealthStatus(HealthStatus.HEALTHY)
        
        async def run_test():
            check = SlowCheck("slow", timeout=0.1)
            result = await check.run_check()
            
            self.assertEqual(result.status, HealthStatus.UNHEALTHY)
            self.assertIn("timed out", result.message)
            self.assertIsNotNone(check.last_result)
            self.assertIsNotNone(check.last_run)
        
        asyncio.run(run_test())
    
    def test_health_check_exception(self):
        class FailingCheck(HealthCheck):
            async def check(self):
                raise ValueError("Test error")
        
        async def run_test():
            check = FailingCheck("failing")
            result = await check.run_check()
            
            self.assertEqual(result.status, HealthStatus.UNHEALTHY)
            self.assertIn("Test error", result.message)
        
        asyncio.run(run_test())


class TestConnectionsHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def test_healthy_connections(self):
        server = MockWebSocketServer(connection_count=50, total_connections=100)
        check = ConnectionsHealthCheck(server, max_connections=1000)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.details["active_connections"], 50)
        self.assertEqual(result.details["total_connections"], 100)
        self.assertEqual(result.details["max_connections"], 1000)
        self.assertEqual(result.details["utilization_percent"], 5.0)
    
    async def test_degraded_connections(self):
        server = MockWebSocketServer(connection_count=850)  # 85% of 1000
        check = ConnectionsHealthCheck(server, max_connections=1000)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.DEGRADED)
        self.assertIn("High connection usage", result.message)
    
    async def test_unhealthy_connections(self):
        server = MockWebSocketServer(connection_count=1000)  # 100% of 1000
        check = ConnectionsHealthCheck(server, max_connections=1000)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("Connection limit reached", result.message)
    
    async def test_connections_check_exception(self):
        server = Mock()
        server.__getattribute__ = Mock(side_effect=Exception("Server error"))
        check = ConnectionsHealthCheck(server)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("Failed to check connections", result.message)


class TestMiddlewareHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def test_healthy_middleware(self):
        middleware = [MockMiddleware(True), MockMiddleware(True)]
        server = MockWebSocketServer(middleware=middleware)
        check = MiddlewareHealthCheck(server)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.details["middleware_count"], 2)
        self.assertIn("MockMiddleware", result.details["middleware_types"])
    
    async def test_unhealthy_middleware(self):
        middleware = [MockMiddleware(True), MockMiddleware(False)]
        server = MockWebSocketServer(middleware=middleware)
        check = MiddlewareHealthCheck(server)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("Unhealthy middleware detected", result.message)
        self.assertIn("unhealthy_middleware", result.details)
    
    async def test_middleware_check_exception(self):
        middleware = [MockMiddleware(True, should_raise=True)]
        server = MockWebSocketServer(middleware=middleware)
        check = MiddlewareHealthCheck(server)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("MockMiddleware", result.details["unhealthy_middleware"][0])
        self.assertIn("error:", result.details["unhealthy_middleware"][0])
    
    async def test_middleware_without_health_check(self):
        class SimpleMiddleware:
            pass
        
        middleware = [SimpleMiddleware()]
        server = MockWebSocketServer(middleware=middleware)
        check = MiddlewareHealthCheck(server)
        
        result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.details["middleware_count"], 1)


class TestMemoryHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def test_memory_check_healthy(self):
        check = MemoryHealthCheck(warning_threshold_mb=1000.0, critical_threshold_mb=2000.0)
        
        with patch('resource.getrusage') as mock_getrusage:
            mock_usage = Mock()
            mock_usage.ru_maxrss = 100 * 1024 * 1024  # 100MB in bytes (macOS)
            mock_getrusage.return_value = mock_usage
            
            with patch('platform.system', return_value='Darwin'):
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertIn("memory_usage_mb", result.details)
        self.assertIn("gc_collections", result.details)
    
    async def test_memory_check_degraded(self):
        check = MemoryHealthCheck(warning_threshold_mb=50.0, critical_threshold_mb=100.0)
        
        with patch('resource.getrusage') as mock_getrusage:
            mock_usage = Mock()
            mock_usage.ru_maxrss = 75 * 1024 * 1024  # 75MB in bytes (macOS)
            mock_getrusage.return_value = mock_usage
            
            with patch('platform.system', return_value='Darwin'):
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.DEGRADED)
        self.assertIn("High memory usage", result.message)
    
    async def test_memory_check_unhealthy(self):
        check = MemoryHealthCheck(warning_threshold_mb=50.0, critical_threshold_mb=75.0)
        
        with patch('resource.getrusage') as mock_getrusage:
            mock_usage = Mock()
            mock_usage.ru_maxrss = 100 * 1024 * 1024  # 100MB in bytes (macOS)
            mock_getrusage.return_value = mock_usage
            
            with patch('platform.system', return_value='Darwin'):
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("Critical memory usage", result.message)
    
    async def test_memory_check_linux(self):
        check = MemoryHealthCheck()
        
        with patch('resource.getrusage') as mock_getrusage:
            mock_usage = Mock()
            mock_usage.ru_maxrss = 100 * 1024  # 100MB in KB (Linux)
            mock_getrusage.return_value = mock_usage
            
            with patch('platform.system', return_value='Linux'):
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertEqual(result.details["memory_usage_mb"], 100.0)


class TestSystemHealthCheck(unittest.IsolatedAsyncioTestCase):
    async def test_system_check_healthy(self):
        check = SystemHealthCheck()
        
        with patch('os.getloadavg', return_value=(0.5, 0.6, 0.7)):
            with patch('shutil.disk_usage') as mock_disk:
                from collections import namedtuple
                DiskUsage = namedtuple('DiskUsage', ['total', 'used', 'free'])
                mock_disk.return_value = DiskUsage(
                    total=1024**4,  # 1TB
                    free=500 * 1024**3,    # 500GB
                    used=524 * 1024**3     # 524GB (~50% usage)
                )
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertIn("load_average_1m", result.details)
        self.assertIn("disk_total_gb", result.details)
    
    async def test_system_check_high_load(self):
        check = SystemHealthCheck(load_threshold=1.0)
        
        with patch('os.getloadavg', return_value=(2.0, 1.5, 1.0)):
            with patch('shutil.disk_usage') as mock_disk:
                from collections import namedtuple
                DiskUsage = namedtuple('DiskUsage', ['total', 'used', 'free'])
                mock_disk.return_value = DiskUsage(
                    total=1024**4, 
                    free=500 * 1024**3, 
                    used=524 * 1024**3
                )
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.DEGRADED)
        self.assertIn("High load average", result.message)
    
    async def test_system_check_high_disk(self):
        check = SystemHealthCheck()
        
        with patch('os.getloadavg', return_value=(0.5, 0.6, 0.7)):
            with patch('shutil.disk_usage') as mock_disk:
                mock_disk.return_value = Mock(
                    total=100 * 1024**3,  # 100GB
                    free=5 * 1024**3,     # 5GB
                    used=95 * 1024**3     # 95GB (95% usage)
                )
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.UNHEALTHY)
        self.assertIn("Critical disk usage", result.message)
    
    async def test_system_check_no_loadavg(self):
        check = SystemHealthCheck()
        
        with patch('os.getloadavg', side_effect=AttributeError):
            with patch('shutil.disk_usage') as mock_disk:
                from collections import namedtuple
                DiskUsage = namedtuple('DiskUsage', ['total', 'used', 'free'])
                mock_disk.return_value = DiskUsage(
                    total=1024**4,  # 1TB
                    free=700 * 1024**3,  # 700GB free (30% usage)
                    used=324 * 1024**3   # 324GB used
                )
                result = await check.check()
        
        self.assertEqual(result.status, HealthStatus.HEALTHY)
        self.assertNotIn("load_average_1m", result.details)


class TestHealthChecker(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.server = MockWebSocketServer()
        self.health_checker = HealthChecker(self.server)
    
    def tearDown(self):
        self.health_checker.stop_http_endpoint()
    
    def test_health_checker_creation(self):
        self.assertIsNotNone(self.health_checker.server)
        self.assertIn("connections", self.health_checker.health_checks)
        self.assertIn("middleware", self.health_checker.health_checks)
        self.assertIn("memory", self.health_checker.health_checks)
        self.assertIn("system", self.health_checker.health_checks)
    
    def test_register_custom_check(self):
        class CustomCheck(HealthCheck):
            async def check(self):
                return HealthStatus(HealthStatus.HEALTHY, "Custom check OK")
        
        custom_check = CustomCheck("custom")
        self.health_checker.register_health_check(custom_check)
        
        self.assertIn("custom", self.health_checker.health_checks)
    
    def test_register_custom_function(self):
        async def custom_function():
            return HealthStatus(HealthStatus.HEALTHY, "Function check OK")
        
        self.health_checker.register_custom_check("custom_func", custom_function)
        
        self.assertIn("custom_func", self.health_checker.custom_checks)
    
    def test_unregister_health_check(self):
        self.health_checker.unregister_health_check("memory")
        
        self.assertNotIn("memory", self.health_checker.health_checks)
    
    async def test_run_all_checks(self):
        results = await self.health_checker.run_all_checks()
        
        self.assertIsInstance(results, dict)
        self.assertIn("connections", results)
        self.assertIn("middleware", results)
        self.assertIn("memory", results)
        self.assertIn("system", results)
        
        for result in results.values():
            self.assertIsInstance(result, HealthStatus)
    
    async def test_overall_health_all_healthy(self):
        for check in self.health_checker.health_checks.values():
            check.check = AsyncMock(return_value=HealthStatus(HealthStatus.HEALTHY))
        
        overall = await self.health_checker.get_overall_health()
        
        self.assertEqual(overall.status, HealthStatus.HEALTHY)
        self.assertIn("checks", overall.details)
        self.assertIn("performance", overall.details)
    
    async def test_overall_health_with_degraded(self):
        self.health_checker.health_checks["memory"].check = AsyncMock(
            return_value=HealthStatus(HealthStatus.DEGRADED, "High memory")
        )
        
        overall = await self.health_checker.get_overall_health()
        
        self.assertEqual(overall.status, HealthStatus.DEGRADED)
        self.assertIn("degraded", overall.message)
    
    async def test_overall_health_with_unhealthy(self):
        self.health_checker.health_checks["system"].check = AsyncMock(
            return_value=HealthStatus(HealthStatus.UNHEALTHY, "System failure")
        )
        
        overall = await self.health_checker.get_overall_health()
        
        self.assertEqual(overall.status, HealthStatus.UNHEALTHY)
        self.assertIn("unhealthy", overall.message)
    
    async def test_custom_check_timeout(self):
        async def slow_custom_check():
            await asyncio.sleep(10)
            return HealthStatus(HealthStatus.HEALTHY)
        
        self.health_checker.register_custom_check("slow", slow_custom_check)
        results = await self.health_checker.run_all_checks()
        
        self.assertEqual(results["slow"].status, HealthStatus.UNHEALTHY)
        self.assertIn("timed out", results["slow"].message)
    
    async def test_custom_check_exception(self):
        async def failing_custom_check():
            raise Exception("Custom check failed")
        
        self.health_checker.register_custom_check("failing", failing_custom_check)
        results = await self.health_checker.run_all_checks()
        
        self.assertEqual(results["failing"].status, HealthStatus.UNHEALTHY)
        self.assertIn("Custom check failed", results["failing"].message)
    
    def test_performance_tracking(self):
        self.health_checker._check_durations["test_check"] = [0.1, 0.2, 0.15]
        
        performance = self.health_checker.get_check_performance("test_check")
        
        self.assertIn("avg_duration_ms", performance)
        self.assertIn("max_duration_ms", performance)
        self.assertIn("min_duration_ms", performance)
        self.assertEqual(performance["samples"], 3)
        self.assertEqual(performance["avg_duration_ms"], 150.0)
    
    async def test_periodic_checks(self):
        self.health_checker.check_interval = 0.1  # 100ms for fast testing
        
        await self.health_checker.start_periodic_checks()
        self.assertIsNotNone(self.health_checker._check_task)
        
        await asyncio.sleep(0.25)
        
        await self.health_checker.stop_periodic_checks()
        self.assertIsNone(self.health_checker._check_task)


class TestHealthCheckerHTTP(unittest.TestCase):
    def setUp(self):
        self.server = MockWebSocketServer()
        self.health_checker = HealthChecker(self.server)
        self.http_port = 9999
        
        self.health_checker.start_http_endpoint(self.http_port)
        time.sleep(0.1)
    
    def tearDown(self):
        self.health_checker.stop_http_endpoint()
    
    def test_health_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/health')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertIn(response.status, [200, 503])
            self.assertIn("status", data)
            self.assertIn("message", data)
            self.assertIn("details", data)
        finally:
            conn.close()
    
    def test_detailed_health_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/health/detailed')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertEqual(response.status, 200)
            self.assertIn("timestamp", data)
            self.assertIn("checks", data)
            self.assertIsInstance(data["checks"], dict)
        finally:
            conn.close()
    
    def test_individual_check_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/health/check/memory')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertIn(response.status, [200, 503])
            self.assertIn("status", data)
            self.assertIn("message", data)
        finally:
            conn.close()
    
    def test_performance_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/health/performance')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertEqual(response.status, 200)
            self.assertIn("timestamp", data)
            self.assertIn("performance", data)
        finally:
            conn.close()
    
    def test_nonexistent_check_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/health/check/nonexistent')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertEqual(response.status, 404)
            self.assertIn("error", data)
        finally:
            conn.close()
    
    def test_invalid_endpoint(self):
        conn = HTTPConnection(f'localhost:{self.http_port}')
        try:
            conn.request('GET', '/invalid')
            response = conn.getresponse()
            data = json.loads(response.read().decode())
            
            self.assertEqual(response.status, 404)
            self.assertIn("error", data)
        finally:
            conn.close()


class TestHealthSetup(unittest.TestCase):
    def test_get_health_checker_singleton(self):
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        checker1 = get_health_checker()
        checker2 = get_health_checker()
        
        self.assertIs(checker1, checker2)
    
    def test_setup_health_checks(self):
        import aiows.health as health_module
        health_module._global_health_checker = None
        
        server = MockWebSocketServer()
        
        checker = setup_health_checks(
            server,
            http_port=9998,
            check_interval=60.0,
            start_periodic=False,
            start_http=False
        )
        
        self.assertIsNotNone(checker)
        self.assertEqual(checker.check_interval, 60.0)
        self.assertEqual(checker.server, server)
        
        checker.stop_http_endpoint()


class TestPerformanceImpact(unittest.IsolatedAsyncioTestCase):
    async def test_health_check_performance(self):
        server = MockWebSocketServer()
        health_checker = HealthChecker(server)
        
        start_time = time.time()
        for _ in range(10):
            await health_checker.run_all_checks()
        end_time = time.time()
        
        total_time = end_time - start_time
        avg_time_per_run = total_time / 10
        
        self.assertLess(avg_time_per_run, 1.0)
        self.assertLess(total_time, 5.0)
    
    async def test_memory_overhead(self):
        import gc
        
        gc.collect()
        initial_objects = len(gc.get_objects())
        
        server = MockWebSocketServer()
        health_checker = HealthChecker(server)
        
        for _ in range(100):
            await health_checker.run_all_checks()
        
        gc.collect()
        final_objects = len(gc.get_objects())
        
        object_growth = final_objects - initial_objects
        self.assertLess(object_growth, 10000)
    
    def test_concurrent_access(self):
        server = MockWebSocketServer()
        health_checker = HealthChecker(server)
        
        async def run_checks():
            for _ in range(10):
                await health_checker.run_all_checks()
                await asyncio.sleep(0.01)
        
        async def run_concurrent_test():
            tasks = [run_checks() for _ in range(5)]
            await asyncio.gather(*tasks)
        
        start_time = time.time()
        asyncio.run(run_concurrent_test())
        end_time = time.time()
        
        self.assertLess(end_time - start_time, 10.0)


if __name__ == '__main__':
    unittest.main() 