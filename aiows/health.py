"""
Health check system for aiows WebSocket framework
"""

import asyncio
import gc
import json
import logging
import os
import resource
import shutil
import threading
import time
import weakref
from collections import defaultdict
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Union, Awaitable
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class HealthStatus:
    """Health status representation"""
    
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    UNHEALTHY = "unhealthy"
    
    def __init__(self, 
                 status: str = HEALTHY,
                 message: str = "",
                 details: Optional[Dict[str, Any]] = None,
                 timestamp: Optional[datetime] = None):
        self.status = status
        self.message = message
        self.details = details or {}
        self.timestamp = timestamp or datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp.isoformat()
        }
    
    def is_healthy(self) -> bool:
        return self.status == self.HEALTHY


class HealthCheck:
    """Base health check interface"""
    
    def __init__(self, name: str, timeout: float = 5.0):
        self.name = name
        self.timeout = timeout
        self.last_result: Optional[HealthStatus] = None
        self.last_run: Optional[datetime] = None
    
    async def check(self) -> HealthStatus:
        raise NotImplementedError("Health check must implement check() method")
    
    async def run_check(self) -> HealthStatus:
        try:
            result = await asyncio.wait_for(self.check(), timeout=self.timeout)
            self.last_result = result
            self.last_run = datetime.now()
            return result
        except asyncio.TimeoutError:
            status = HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Health check '{self.name}' timed out after {self.timeout}s"
            )
            self.last_result = status
            self.last_run = datetime.now()
            return status
        except Exception as e:
            status = HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Health check '{self.name}' failed: {str(e)}"
            )
            self.last_result = status
            self.last_run = datetime.now()
            return status


class ConnectionsHealthCheck(HealthCheck):
    """Monitor active WebSocket connections"""
    
    def __init__(self, server_instance, max_connections: int = 1000):
        super().__init__("connections")
        self.server = server_instance
        self.max_connections = max_connections
    
    async def check(self) -> HealthStatus:
        try:
            connection_count = getattr(self.server, '_connection_count', 0)
            total_connections = getattr(self.server, '_total_connections', 0)
            
            details = {
                "active_connections": connection_count,
                "total_connections": total_connections,
                "max_connections": self.max_connections,
                "utilization_percent": round((connection_count / self.max_connections) * 100, 2) if self.max_connections > 0 else 0
            }
            
            if connection_count >= self.max_connections:
                return HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Connection limit reached: {connection_count}/{self.max_connections}",
                    details=details
                )
            elif connection_count >= self.max_connections * 0.8:
                return HealthStatus(
                    status=HealthStatus.DEGRADED,
                    message=f"High connection usage: {connection_count}/{self.max_connections}",
                    details=details
                )
            else:
                return HealthStatus(
                    status=HealthStatus.HEALTHY,
                    message=f"Connection usage normal: {connection_count}/{self.max_connections}",
                    details=details
                )
        except Exception as e:
            return HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check connections: {str(e)}"
            )


class MiddlewareHealthCheck(HealthCheck):
    """Monitor middleware health"""
    
    def __init__(self, server_instance):
        super().__init__("middleware")
        self.server = server_instance
    
    async def check(self) -> HealthStatus:
        try:
            middleware_list = getattr(self.server, '_middleware', [])
            middleware_count = len(middleware_list)
            
            details = {
                "middleware_count": middleware_count,
                "middleware_types": [type(mw).__name__ for mw in middleware_list]
            }
            
            unhealthy_middleware = []
            for middleware in middleware_list:
                if hasattr(middleware, 'health_check'):
                    try:
                        result = await middleware.health_check()
                        if not result:
                            unhealthy_middleware.append(type(middleware).__name__)
                    except Exception as e:
                        unhealthy_middleware.append(f"{type(middleware).__name__} (error: {str(e)})")
            
            if unhealthy_middleware:
                details["unhealthy_middleware"] = unhealthy_middleware
                return HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Unhealthy middleware detected: {', '.join(unhealthy_middleware)}",
                    details=details
                )
            
            return HealthStatus(
                status=HealthStatus.HEALTHY,
                message=f"All {middleware_count} middleware healthy",
                details=details
            )
        except Exception as e:
            return HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check middleware: {str(e)}"
            )


class MemoryHealthCheck(HealthCheck):
    """Monitor memory usage using standard library"""
    
    def __init__(self, warning_threshold_mb: float = 500.0, critical_threshold_mb: float = 1000.0):
        super().__init__("memory")
        self.warning_threshold_mb = warning_threshold_mb
        self.critical_threshold_mb = critical_threshold_mb
    
    async def check(self) -> HealthStatus:
        try:
            usage = resource.getrusage(resource.RUSAGE_SELF)
            memory_usage_kb = usage.ru_maxrss
            
            import platform
            if platform.system() == 'Darwin':
                memory_usage_mb = memory_usage_kb / 1024 / 1024
            else:
                memory_usage_mb = memory_usage_kb / 1024
            
            gc_stats = gc.get_stats()
            total_collections = sum(stat['collections'] for stat in gc_stats)
            
            details = {
                "memory_usage_mb": round(memory_usage_mb, 2),
                "max_memory_usage_mb": round(memory_usage_mb, 2),
                "gc_collections": total_collections,
                "gc_generations": len(gc_stats),
                "warning_threshold_mb": self.warning_threshold_mb,
                "critical_threshold_mb": self.critical_threshold_mb
            }
            
            if memory_usage_mb >= self.critical_threshold_mb:
                return HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Critical memory usage: {memory_usage_mb:.1f}MB",
                    details=details
                )
            elif memory_usage_mb >= self.warning_threshold_mb:
                return HealthStatus(
                    status=HealthStatus.DEGRADED,
                    message=f"High memory usage: {memory_usage_mb:.1f}MB",
                    details=details
                )
            else:
                return HealthStatus(
                    status=HealthStatus.HEALTHY,
                    message=f"Memory usage normal: {memory_usage_mb:.1f}MB",
                    details=details
                )
        except Exception as e:
            return HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check memory: {str(e)}"
            )


class SystemHealthCheck(HealthCheck):
    """Monitor system health using standard library"""
    
    def __init__(self, load_threshold: float = 2.0):
        super().__init__("system")
        self.load_threshold = load_threshold
    
    async def check(self) -> HealthStatus:
        try:
            details = {}
            issues = []
            status = HealthStatus.HEALTHY
            
            try:
                if hasattr(os, 'getloadavg'):
                    load_avg = os.getloadavg()
                    details["load_average_1m"] = load_avg[0]
                    details["load_average_5m"] = load_avg[1]
                    details["load_average_15m"] = load_avg[2]
                    
                    if load_avg[0] >= self.load_threshold:
                        issues.append(f"High load average: {load_avg[0]:.2f}")
                        status = HealthStatus.DEGRADED
            except (AttributeError, OSError):
                pass
            
            try:
                disk_usage = shutil.disk_usage('/')
                disk_total_gb = disk_usage.total / 1024 / 1024 / 1024
                disk_free_gb = disk_usage.free / 1024 / 1024 / 1024
                disk_used_percent = ((disk_usage.total - disk_usage.free) / disk_usage.total) * 100
                
                details.update({
                    "disk_total_gb": round(disk_total_gb, 2),
                    "disk_free_gb": round(disk_free_gb, 2),
                    "disk_used_percent": round(disk_used_percent, 2)
                })
                
                if disk_used_percent >= 90:
                    issues.append(f"Critical disk usage: {disk_used_percent:.1f}%")
                    status = HealthStatus.UNHEALTHY
                elif disk_used_percent >= 80:
                    issues.append(f"High disk usage: {disk_used_percent:.1f}%")
                    if status == HealthStatus.HEALTHY:
                        status = HealthStatus.DEGRADED
            except Exception as e:
                issues.append(f"Disk check failed: {str(e)}")
                if status == HealthStatus.HEALTHY:
                    status = HealthStatus.DEGRADED
            
            try:
                soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
                details.update({
                    "fd_soft_limit": soft_limit,
                    "fd_hard_limit": hard_limit
                })
            except Exception:
                pass
            
            if issues:
                message = "; ".join(issues)
            else:
                message = "System resources normal"
            
            return HealthStatus(
                status=status,
                message=message,
                details=details
            )
        except Exception as e:
            return HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"Failed to check system: {str(e)}"
            )


class HealthChecker:
    """Main health checker class"""
    
    def __init__(self, server_instance=None):
        self.server = server_instance
        self.health_checks: Dict[str, HealthCheck] = {}
        self.custom_checks: Dict[str, Callable[[], Awaitable[HealthStatus]]] = {}
        self.check_interval = 30.0
        self.enabled = True
        self._check_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        self._http_server: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None
        self.http_port = 8080
        
        self._check_durations: Dict[str, List[float]] = defaultdict(list)
        self._max_duration_history = 10
        
        self._register_builtin_checks()
    
    def _register_builtin_checks(self):
        if self.server is not None:
            self.health_checks["connections"] = ConnectionsHealthCheck(self.server)
            self.health_checks["middleware"] = MiddlewareHealthCheck(self.server)
        
        self.health_checks["memory"] = MemoryHealthCheck()
        self.health_checks["system"] = SystemHealthCheck()
    
    def register_health_check(self, check: HealthCheck):
        self.health_checks[check.name] = check
    
    def register_custom_check(self, name: str, check_func: Callable[[], Awaitable[HealthStatus]]):
        self.custom_checks[name] = check_func
    
    def unregister_health_check(self, name: str):
        self.health_checks.pop(name, None)
        self.custom_checks.pop(name, None)
        self._check_durations.pop(name, None)
    
    def get_check_performance(self, check_name: str) -> Dict[str, float]:
        durations = self._check_durations.get(check_name, [])
        if not durations:
            return {}
        
        return {
            "avg_duration_ms": round(sum(durations) / len(durations) * 1000, 2),
            "max_duration_ms": round(max(durations) * 1000, 2),
            "min_duration_ms": round(min(durations) * 1000, 2),
            "samples": len(durations)
        }
    
    async def run_all_checks(self) -> Dict[str, HealthStatus]:
        results = {}
        
        for name, check in self.health_checks.items():
            try:
                start_time = time.time()
                results[name] = await check.run_check()
                duration = time.time() - start_time
                
                self._check_durations[name].append(duration)
                if len(self._check_durations[name]) > self._max_duration_history:
                    self._check_durations[name].pop(0)
                    
            except Exception as e:
                results[name] = HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Health check '{name}' failed: {str(e)}"
                )
        
        for name, check_func in self.custom_checks.items():
            try:
                start_time = time.time()
                results[name] = await asyncio.wait_for(check_func(), timeout=5.0)
                duration = time.time() - start_time
                
                self._check_durations[name].append(duration)
                if len(self._check_durations[name]) > self._max_duration_history:
                    self._check_durations[name].pop(0)
                    
            except asyncio.TimeoutError:
                results[name] = HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Custom health check '{name}' timed out"
                )
            except Exception as e:
                results[name] = HealthStatus(
                    status=HealthStatus.UNHEALTHY,
                    message=f"Custom health check '{name}' failed: {str(e)}"
                )
        
        return results
    
    async def get_overall_health(self) -> HealthStatus:
        check_results = await self.run_all_checks()
        
        if not check_results:
            return HealthStatus(
                status=HealthStatus.HEALTHY,
                message="No health checks configured"
            )
        
        unhealthy_count = sum(1 for result in check_results.values() 
                             if result.status == HealthStatus.UNHEALTHY)
        degraded_count = sum(1 for result in check_results.values()
                            if result.status == HealthStatus.DEGRADED)
        healthy_count = len(check_results) - unhealthy_count - degraded_count
        
        performance = {name: self.get_check_performance(name) 
                      for name in check_results.keys()}
        
        details = {
            "total_checks": len(check_results),
            "healthy": healthy_count,
            "degraded": degraded_count,
            "unhealthy": unhealthy_count,
            "checks": {name: result.to_dict() for name, result in check_results.items()},
            "performance": performance
        }
        
        if unhealthy_count > 0:
            return HealthStatus(
                status=HealthStatus.UNHEALTHY,
                message=f"{unhealthy_count} unhealthy check(s), {degraded_count} degraded",
                details=details
            )
        elif degraded_count > 0:
            return HealthStatus(
                status=HealthStatus.DEGRADED,
                message=f"{degraded_count} degraded check(s), {healthy_count} healthy",
                details=details
            )
        else:
            return HealthStatus(
                status=HealthStatus.HEALTHY,
                message=f"All {healthy_count} checks healthy",
                details=details
            )
    
    async def start_periodic_checks(self):
        if self._check_task is not None:
            return
        
        self._check_task = asyncio.create_task(self._periodic_check_loop())
        logger.info("Started periodic health checks")
    
    async def stop_periodic_checks(self):
        if self._check_task is not None:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
            self._check_task = None
            logger.info("Stopped periodic health checks")
    
    async def _periodic_check_loop(self):
        while self.enabled:
            try:
                async with self._lock:
                    await self.run_all_checks()
                await asyncio.sleep(self.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic health check: {e}")
                await asyncio.sleep(5)
    
    def start_http_endpoint(self, port: int = 8080):
        if self._http_server is not None:
            return
        
        self.http_port = port
        
        class HealthHandler(BaseHTTPRequestHandler):
            def __init__(self, health_checker, *args, **kwargs):
                self.health_checker = health_checker
                super().__init__(*args, **kwargs)
            
            def do_GET(self):
                try:
                    parsed_url = urlparse(self.path)
                    
                    if parsed_url.path == '/health':
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            health_status = loop.run_until_complete(
                                self.health_checker.get_overall_health()
                            )
                            status_code = 200 if health_status.is_healthy() else 503
                            self._send_json_response(status_code, health_status.to_dict())
                        finally:
                            loop.close()
                    
                    elif parsed_url.path == '/health/detailed':
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            check_results = loop.run_until_complete(
                                self.health_checker.run_all_checks()
                            )
                            response = {
                                "timestamp": datetime.now().isoformat(),
                                "checks": {name: result.to_dict() for name, result in check_results.items()}
                            }
                            self._send_json_response(200, response)
                        finally:
                            loop.close()
                    
                    elif parsed_url.path.startswith('/health/check/'):
                        check_name = parsed_url.path.split('/')[-1]
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            if check_name in self.health_checker.health_checks:
                                result = loop.run_until_complete(
                                    self.health_checker.health_checks[check_name].run_check()
                                )
                                status_code = 200 if result.is_healthy() else 503
                                self._send_json_response(status_code, result.to_dict())
                            elif check_name in self.health_checker.custom_checks:
                                result = loop.run_until_complete(
                                    self.health_checker.custom_checks[check_name]()
                                )
                                status_code = 200 if result.is_healthy() else 503
                                self._send_json_response(status_code, result.to_dict())
                            else:
                                self._send_json_response(404, {"error": f"Health check '{check_name}' not found"})
                        finally:
                            loop.close()
                    
                    elif parsed_url.path == '/health/performance':
                        performance = {}
                        for name in list(self.health_checker.health_checks.keys()) + list(self.health_checker.custom_checks.keys()):
                            performance[name] = self.health_checker.get_check_performance(name)
                        
                        response = {
                            "timestamp": datetime.now().isoformat(),
                            "performance": performance
                        }
                        self._send_json_response(200, response)
                    
                    else:
                        self._send_json_response(404, {"error": "Not found"})
                
                except Exception as e:
                    logger.error(f"Error in health endpoint: {e}")
                    self._send_json_response(500, {"error": str(e)})
            
            def _send_json_response(self, status_code, data):
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(json.dumps(data, indent=2).encode())
            
            def log_message(self, format, *args):
                pass
        
        def create_handler(*args, **kwargs):
            return HealthHandler(self, *args, **kwargs)
        
        def run_server():
            try:
                self._http_server = HTTPServer(('', port), create_handler)
                logger.info(f"Started health check HTTP server on port {port}")
                self._http_server.serve_forever()
            except Exception as e:
                logger.error(f"Health check HTTP server error: {e}")
        
        self._http_thread = threading.Thread(target=run_server, daemon=True)
        self._http_thread.start()
    
    def stop_http_endpoint(self):
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server = None
            logger.info("Stopped health check HTTP server")
        
        if self._http_thread is not None:
            self._http_thread.join(timeout=5)
            self._http_thread = None


_global_health_checker: Optional[HealthChecker] = None


def get_health_checker(server_instance=None) -> HealthChecker:
    global _global_health_checker
    
    if _global_health_checker is None:
        _global_health_checker = HealthChecker(server_instance)
    
    return _global_health_checker


def setup_health_checks(server_instance, 
                       http_port: int = 8080,
                       check_interval: float = 30.0,
                       start_periodic: bool = True,
                       start_http: bool = True) -> HealthChecker:
    health_checker = get_health_checker(server_instance)
    health_checker.check_interval = check_interval
    
    if start_http:
        health_checker.start_http_endpoint(http_port)
    
    if start_periodic:
        asyncio.create_task(health_checker.start_periodic_checks())
    
    return health_checker 