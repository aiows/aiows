"""
WebSocket server implementation with SSL/TLS support
"""

import asyncio
import atexit
import logging
import os
import signal
import ssl
import subprocess
import tempfile
import time
import warnings
import websockets
from typing import Dict, List, Optional, Union, TYPE_CHECKING, Set, Any
from .router import Router
from .dispatcher import MessageDispatcher
from .websocket import WebSocket
from .middleware.base import BaseMiddleware

if TYPE_CHECKING:
    from .settings import AiowsSettings

logger = logging.getLogger(__name__)


class CertificateManager:
    """Simple certificate manager for SSL/TLS support"""
    
    _temp_files = []
    
    @classmethod
    def cleanup_temp_files(cls):
        for file_path in cls._temp_files:
            try:
                if os.path.exists(file_path):
                    os.unlink(file_path)
                    logger.debug(f"Cleaned up temp file: {file_path}")
            except Exception as e:
                logger.warning(f"Failed to cleanup {file_path}: {e}")
        cls._temp_files.clear()
    
    @classmethod
    def generate_self_signed_cert(cls, 
                                 common_name: str = "localhost",
                                 org_name: str = "aiows Development",
                                 country: str = "US",
                                 days: int = 365) -> tuple[str, str]:
        cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(suffix='.key', delete=False)
        cert_file.close()
        key_file.close()
        
        cls._temp_files.extend([cert_file.name, key_file.name])
        
        try:
            cmd = [
                'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                '-keyout', key_file.name, '-out', cert_file.name,
                '-days', str(days), '-nodes',
                '-subj', f'/C={country}/O={org_name}/CN={common_name}',
                '-addext', f'subjectAltName=DNS:{common_name},DNS:127.0.0.1,IP:127.0.0.1,IP:::1'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                raise RuntimeError(f"Certificate generation failed: {result.stderr}")
            
            logger.info(f"Generated self-signed certificate for {common_name}")
            return cert_file.name, key_file.name
            
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            try:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)
            except:
                pass
            raise RuntimeError(f"OpenSSL not available or timed out: {e}")
    
    @classmethod
    def create_secure_ssl_context(cls, cert_file: str, key_file: str) -> ssl.SSLContext:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        context.load_cert_chain(cert_file, key_file)
        
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        return context
    
    @classmethod
    def validate_certificate(cls, cert_file: str) -> Dict[str, Union[str, bool]]:
        try:
            cmd = ['openssl', 'x509', '-in', cert_file, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {'valid': False, 'error': 'Invalid certificate format'}
            
            output = result.stdout
            return {
                'valid': True,
                'has_san': 'Subject Alternative Name' in output,
                'has_ipv6': ':::1' in output or 'IP Address:0:0:0:0:0:0:0:1' in output,
                'subject': 'CN=' in output
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}


atexit.register(CertificateManager.cleanup_temp_files)


class WebSocketServer:
    """Main WebSocket server class for aiows framework with SSL/TLS support"""
    
    def __init__(self, 
                 ssl_context: Optional[ssl.SSLContext] = None,
                 is_production: bool = False,
                 require_ssl_in_production: bool = True,
                 cert_config: Optional[Dict[str, str]] = None,
                 settings: Optional['AiowsSettings'] = None):
        if settings is None:
            try:
                from .settings import create_settings
                settings = create_settings()
            except ImportError:
                settings = None
        
        if settings is not None:
            self.host: str = settings.server.host
            self.port: int = settings.server.port
            self._cleanup_interval: float = settings.server.cleanup_interval
            self._shutdown_timeout: float = settings.server.shutdown_timeout
            
            if ssl_context is None and hasattr(settings.server, 'ssl_context'):
                ssl_context = getattr(settings.server, 'ssl_context', None)
            
            is_production = settings.server.is_production
            require_ssl_in_production = settings.server.require_ssl_in_production
            
            if not cert_config:
                cert_config = {
                    'common_name': settings.server.ssl_cert_common_name,
                    'org_name': settings.server.ssl_cert_org_name,
                    'country': settings.server.ssl_cert_country,
                    'days': settings.server.ssl_cert_days
                }
        else:
            self.host: str = "localhost"
            self.port: int = 8000
            self._cleanup_interval: float = 30.0
            self._shutdown_timeout: float = 30.0
        
        self.router: Router = Router()
        self.dispatcher: MessageDispatcher = MessageDispatcher(self.router)
        
        self._connections: Set[WebSocket] = set()
        self._connection_count: int = 0
        self._total_connections: int = 0
        self._connections_lock: asyncio.Lock = asyncio.Lock()
        self._cleanup_task: Optional[asyncio.Task] = None
        
        self._middleware: List[BaseMiddleware] = []
        
        self.ssl_context = ssl_context
        self.is_production = is_production
        self.require_ssl_in_production = require_ssl_in_production
        self.cert_config = cert_config or {}
        self._ssl_cert_files: Optional[tuple[str, str]] = None
        
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._server_task: Optional[asyncio.Task] = None
        self._signal_handlers_registered: bool = False
        
        self._settings = settings
        
        self._validate_ssl_configuration()
    
    @classmethod
    def from_settings(cls, settings: 'AiowsSettings', ssl_context: Optional[ssl.SSLContext] = None) -> 'WebSocketServer':
        return cls(
            ssl_context=ssl_context,
            settings=settings
        )
    
    def get_active_connections_count(self) -> int:
        return len(self._connections)
    
    def get_total_connections_count(self) -> int:
        return self._total_connections
    
    def get_connection_stats(self) -> Dict[str, int]:
        active_count = len(self._connections)
        return {
            'active_connections': active_count,
            'total_connections': self._total_connections,
            'connection_count_tracked': self._connection_count
        }
    
    def get_backpressure_stats(self) -> Dict[str, Any]:
        from .websocket import backpressure_metrics
        
        stats = {
            'global_stats': backpressure_metrics.get_global_stats(),
            'connection_stats': []
        }
        
        for ws in list(self._connections):
            try:
                if hasattr(ws, 'get_backpressure_stats'):
                    conn_stats = ws.get_backpressure_stats()
                    stats['connection_stats'].append(conn_stats)
            except Exception as e:
                logger.debug(f"Error getting backpressure stats for connection: {e}")
        
        return stats
    
    def get_slow_connections(self) -> List[Dict[str, Any]]:
        slow_connections = []
        
        for ws in list(self._connections):
            try:
                if hasattr(ws, 'get_backpressure_stats'):
                    stats = ws.get_backpressure_stats()
                    if stats.get('is_slow_client', False):
                        slow_connections.append(stats)
            except Exception as e:
                logger.debug(f"Error checking slow connection: {e}")
        
        return slow_connections
    
    async def _start_periodic_cleanup(self) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup_loop())
            logger.debug("Started periodic connection cleanup task")
    
    async def _stop_periodic_cleanup(self) -> None:
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.debug("Stopped periodic connection cleanup task")
    
    async def _periodic_cleanup_loop(self) -> None:
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(self._cleanup_interval)
                if self._shutdown_event.is_set():
                    break
                await self._cleanup_dead_connections()
        except asyncio.CancelledError:
            logger.debug("Periodic cleanup task cancelled")
        except Exception as e:
            logger.warning(f"Error in periodic cleanup: {e}")
    
    async def _cleanup_dead_connections(self) -> None:
        try:
            async with self._connections_lock:
                dead_connections = []
                
                for ws in list(self._connections):
                    try:
                        if hasattr(ws, 'closed') and ws.closed:
                            dead_connections.append(ws)
                    except Exception as e:
                        logger.debug(f"Error checking connection state: {e}")
                        dead_connections.append(ws)
                
                removed_count = 0
                for ws in dead_connections:
                    if ws in self._connections:
                        self._connections.discard(ws)
                        removed_count += 1
                
                self._connection_count = max(0, self._connection_count - removed_count)
                
                if __debug__:
                    assert len(self._connections) == self._connection_count, f"Connection count mismatch after cleanup: {len(self._connections)} != {self._connection_count}"
                
                if removed_count > 0:
                    logger.debug(f"Cleaned up {removed_count} dead connections")
                
        except Exception as e:
            logger.warning(f"Error during dead connection cleanup: {e}")
    
    async def _add_connection(self, ws: WebSocket) -> None:
        try:
            async with self._connections_lock:
                self._connections.add(ws)
                self._connection_count += 1
                self._total_connections += 1
                
                if __debug__:
                    assert len(self._connections) == self._connection_count, f"Connection count mismatch after add: {len(self._connections)} != {self._connection_count}"
                
                logger.debug(f"Added connection, active: {len(self._connections)}, total: {self._total_connections}")
        except Exception as e:
            logger.warning(f"Error adding connection: {e}")
    
    async def _remove_connection(self, ws: WebSocket) -> None:
        try:
            async with self._connections_lock:
                if ws in self._connections:
                    self._connections.discard(ws)
                    self._connection_count = max(0, self._connection_count - 1)
                    
                    if __debug__:
                        assert len(self._connections) == self._connection_count, f"Connection count mismatch after remove: {len(self._connections)} != {self._connection_count}"
                    
                    logger.debug(f"Removed connection, active: {len(self._connections)}")
        except Exception as e:
            logger.warning(f"Error removing connection: {e}")
    
    def _validate_ssl_configuration(self) -> None:
        if self.is_production and self.require_ssl_in_production and not self.ssl_context:
            raise ValueError(
                "SSL context is required in production environment. "
                "Either provide ssl_context or set require_ssl_in_production=False"
            )
        
        if not self.ssl_context and not self.is_production:
            warnings.warn(
                "Running without SSL encryption. "
                "This is acceptable for development but NEVER use in production!",
                UserWarning,
                stacklevel=3
            )
    
    def create_development_ssl_context(self, 
                                     cert_file: Optional[str] = None,
                                     key_file: Optional[str] = None) -> ssl.SSLContext:
        try:
            if cert_file is None or key_file is None:
                cert_file, key_file = CertificateManager.generate_self_signed_cert(
                    common_name=self.cert_config.get('common_name', 'localhost'),
                    org_name=self.cert_config.get('org_name', 'aiows Development'),
                    country=self.cert_config.get('country', 'US'),
                    days=self.cert_config.get('days', 365)
                )
                self._ssl_cert_files = (cert_file, key_file)
            
            ssl_context = CertificateManager.create_secure_ssl_context(cert_file, key_file)
            
            warnings.warn(
                "Using self-signed certificate for development. "
                "This provides encryption but NOT authentication. "
                "Use proper certificates in production!",
                UserWarning,
                stacklevel=2
            )
            
            return ssl_context
            
        except Exception as e:
            logger.error(f"Failed to create development SSL context: {e}")
            raise
    
    def enable_development_ssl(self) -> None:
        if self.ssl_context is not None:
            warnings.warn("SSL context already configured", UserWarning)
            return
        
        try:
            self.ssl_context = self.create_development_ssl_context()
            logger.info("Development SSL enabled with self-signed certificate")
        except Exception as e:
            logger.error(f"Failed to enable development SSL: {e}")
            raise
    
    @property
    def is_ssl_enabled(self) -> bool:
        return self.ssl_context is not None
    
    @property  
    def protocol(self) -> str:
        return "wss" if self.is_ssl_enabled else "ws"
    
    def validate_ssl_certificate(self) -> Dict[str, Union[str, bool]]:
        if not self.is_ssl_enabled:
            return {'valid': False, 'error': 'SSL not enabled'}
        
        if not self._ssl_cert_files:
            return {'valid': False, 'error': 'No certificate files tracked'}
        
        cert_file, _ = self._ssl_cert_files
        return CertificateManager.validate_certificate(cert_file)
    
    def reload_ssl_certificate(self, cert_file: str, key_file: str) -> bool:
        try:
            validation = CertificateManager.validate_certificate(cert_file)
            if not validation.get('valid', False):
                logger.error(f"Certificate validation failed: {validation.get('error')}")
                return False
            
            new_context = CertificateManager.create_secure_ssl_context(cert_file, key_file)
            
            old_context = self.ssl_context
            self.ssl_context = new_context
            self._ssl_cert_files = (cert_file, key_file)
            
            logger.info(f"SSL certificate reloaded successfully from {cert_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload SSL certificate: {e}")
            return False
    
    def _setup_signal_handlers(self) -> None:
        if self._signal_handlers_registered:
            return
        
        try:
            loop = asyncio.get_running_loop()
            
            def sigterm_handler():
                logger.info("Received SIGTERM, initiating graceful shutdown...")
                asyncio.create_task(self.shutdown())
            
            def sigint_handler():
                logger.info("Received SIGINT (Ctrl+C), initiating graceful shutdown...")
                asyncio.create_task(self.shutdown())
            
            loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
            loop.add_signal_handler(signal.SIGINT, sigint_handler)
            
            self._signal_handlers_registered = True
            logger.debug("Signal handlers registered for graceful shutdown")
            
        except Exception as e:
            logger.warning(f"Could not register signal handlers: {e}")
    
    async def shutdown(self, timeout: Optional[float] = None) -> None:
        if self._shutdown_event.is_set():
            logger.debug("Shutdown already in progress")
            return
        
        shutdown_timeout = timeout or self._shutdown_timeout
        logger.info(f"Starting graceful shutdown (timeout: {shutdown_timeout}s)")
        
        self._shutdown_event.set()
        
        await self._stop_periodic_cleanup()
        
        await self._close_all_connections(shutdown_timeout / 2)
        
        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
            try:
                await asyncio.wait_for(self._server_task, timeout=shutdown_timeout / 4)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.debug("Server task cancelled or timed out")
        
        await self._cleanup_resources()
        
        logger.info("Graceful shutdown completed")
    
    async def _close_all_connections(self, timeout: float) -> None:
        async with self._connections_lock:
            if not self._connections:
                return
            connection_count = len(self._connections)
            connections_snapshot = list(self._connections)
        
        logger.info(f"Closing {connection_count} active connections...")
        start_time = time.time()
        
        close_tasks = []
        
        for ws in connections_snapshot:
            try:
                if not ws.closed:
                    task = asyncio.create_task(self._close_connection_gracefully(ws))
                    close_tasks.append(task)
            except Exception as e:
                logger.debug(f"Error initiating close for connection: {e}")
                await self._remove_connection(ws)
        
        if close_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                logger.warning(f"Connection close timeout after {elapsed:.1f}s, forcing closure")
                
                async with self._connections_lock:
                    remaining_connections = list(self._connections)
                
                for ws in remaining_connections:
                    try:
                        if not ws.closed:
                            asyncio.create_task(ws.close(code=1001, reason="Server shutdown"))
                        await self._remove_connection(ws)
                    except Exception as e:
                        logger.debug(f"Error force-closing connection: {str(e)}")
                        await self._remove_connection(ws)
        
        for _ in range(10):
            async with self._connections_lock:
                if not self._connections:
                    break
                remaining = len(self._connections)
            await asyncio.sleep(0.1)
        
        async with self._connections_lock:
            remaining = len(self._connections)
            if remaining > 0:
                logger.warning(f"{remaining} connections did not close gracefully")
                self._connections.clear()
                self._connection_count = 0
            else:
                logger.info("All connections closed successfully")
    
    async def _close_connection_gracefully(self, ws: WebSocket) -> None:
        try:
            await self.dispatcher.dispatch_disconnect(ws, "Server shutdown")
        except Exception as e:
            logger.debug(f"Error in disconnect handler: {e}")
        
        try:
            if not ws.closed:
                await ws.close(code=1001, reason="Server shutdown")
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")
        finally:
            await self._remove_connection(ws)
    
    async def _cleanup_resources(self) -> None:
        try:
            await self._cleanup_dead_connections()
            
            async with self._connections_lock:
                self._connections.clear()
                self._connection_count = 0
            
            if hasattr(CertificateManager, 'cleanup_temp_files'):
                CertificateManager.cleanup_temp_files()
            
            logger.debug("Resource cleanup completed")
            
        except Exception as e:
            logger.warning(f"Error during resource cleanup: {e}")
    
    def set_shutdown_timeout(self, timeout: float) -> None:
        if timeout <= 0:
            raise ValueError("Shutdown timeout must be positive")
        self._shutdown_timeout = timeout
        logger.debug(f"Shutdown timeout set to {timeout}s")
    
    @property
    def is_shutting_down(self) -> bool:
        return self._shutdown_event.is_set()
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        self._middleware.append(middleware)
        self._update_dispatcher_middleware()
    
    def _update_dispatcher_middleware(self) -> None:
        self.dispatcher._middleware.clear()
        
        for middleware in self._middleware:
            self.dispatcher.add_middleware(middleware)
        
        for middleware in self.router.get_all_middleware():
            self.dispatcher.add_middleware(middleware)
    
    def include_router(self, router: Router) -> None:
        self.router = router
        self.dispatcher = MessageDispatcher(self.router)
        self._update_dispatcher_middleware()
    
    async def _handle_connection(self, websocket) -> None:
        backpressure_settings = None
        if self._settings and hasattr(self._settings, 'backpressure'):
            backpressure_config = self._settings.backpressure
            backpressure_settings = {
                'enabled': backpressure_config.enabled,
                'send_queue_max_size': backpressure_config.send_queue_max_size,
                'send_queue_overflow_strategy': backpressure_config.send_queue_overflow_strategy,
                'slow_client_threshold': backpressure_config.slow_client_threshold,
                'slow_client_timeout': backpressure_config.slow_client_timeout,
                'max_response_time_ms': backpressure_config.max_response_time_ms,
                'enable_send_metrics': backpressure_config.enable_send_metrics
            }
        
        ws_wrapper = WebSocket(websocket, backpressure_settings=backpressure_settings)
        connection_added = False
        
        try:
            await self._add_connection(ws_wrapper)
            connection_added = True
            
            await self.dispatcher.dispatch_connect(ws_wrapper)
            
            while not ws_wrapper.closed and not self._shutdown_event.is_set():
                try:
                    try:
                        message_data = await ws_wrapper.receive_json()
                        await self.dispatcher.dispatch_message(ws_wrapper, message_data)
                    except asyncio.TimeoutError:
                        continue
                        
                except Exception as e:
                    if self._shutdown_event.is_set():
                        logger.debug("Connection closed during shutdown")
                        break
                    
                    if "1000 (OK)" not in str(e) and "1001" not in str(e):
                        logger.debug(f"Error processing message: {str(e)}")
                    break
                    
        except Exception as e:
            if not self._shutdown_event.is_set():
                logger.debug(f"Connection error: {str(e)}")
        finally:
            cleanup_error = None
            
            if connection_added:
                async with self._connections_lock:
                    in_connections = ws_wrapper in self._connections
                
                if in_connections:
                    reason = "Server shutdown" if self._shutdown_event.is_set() else "Connection closed"
                    try:
                        await self.dispatcher.dispatch_disconnect(ws_wrapper, reason)
                    except Exception as e:
                        cleanup_error = e
                        logger.debug(f"Error in disconnect handler: {str(e)}")
            
            if connection_added:
                try:
                    await self._remove_connection(ws_wrapper)
                except Exception as e:
                    if cleanup_error is None:
                        cleanup_error = e
                    logger.debug(f"Error removing connection: {str(e)}")
            
            if not ws_wrapper.closed:
                try:
                    close_code = 1001 if self._shutdown_event.is_set() else 1000
                    await ws_wrapper.close(code=close_code)
                except Exception as e:
                    if cleanup_error is None:
                        cleanup_error = e
                    logger.debug(f"Error closing connection: {str(e)}")
            
            if cleanup_error:
                logger.debug(f"Connection cleanup completed with errors: {cleanup_error}")
    
    def run(self, host: str = "localhost", port: int = 8000) -> None:
        self.host = host
        self.port = port
        
        if self.is_ssl_enabled:
            logger.info(f"Starting secure WebSocket server on {self.protocol}://{host}:{port}")
            if self._ssl_cert_files:
                validation = self.validate_ssl_certificate()
                if validation.get('valid'):
                    logger.info(f"SSL certificate validated - IPv6: {validation.get('has_ipv6', False)}, SAN: {validation.get('has_san', False)}")
                else:
                    logger.warning(f"SSL certificate validation failed: {validation.get('error')}")
        else:
            logger.warning(f"Starting WebSocket server on {self.protocol}://{host}:{port} (UNENCRYPTED)")
            if self.is_production:
                logger.error("CRITICAL: Running without SSL in production environment!")
        
        try:
            asyncio.run(self._run_server_with_shutdown(host, port))
        except KeyboardInterrupt:
            logger.info("Server shutdown requested via KeyboardInterrupt")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
    
    async def _run_server_with_shutdown(self, host: str, port: int) -> None:
        self._setup_signal_handlers()
        
        self._shutdown_event.clear()
        
        await self._start_periodic_cleanup()
        
        try:
            self._server_task = asyncio.create_task(self._run_server(host, port, wait_for_shutdown=True))
            
            done, pending = await asyncio.wait(
                [self._server_task, asyncio.create_task(self._shutdown_event.wait())],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            if self._shutdown_event.is_set():
                logger.info("Shutdown event triggered, starting graceful shutdown...")
                await self.shutdown()
            
            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                    
        except Exception as e:
            logger.error(f"Server error during shutdown-aware run: {e}")
            raise
        finally:
            await self._stop_periodic_cleanup()
            if not self._shutdown_event.is_set():
                await self._cleanup_resources()

    async def _run_server(self, host: str, port: int, wait_for_shutdown: bool = True) -> None:
        async def connection_handler(websocket):
            await self._handle_connection(websocket)
        
        serve_kwargs = {
            'host': host,
            'port': port
        }
        
        if self.ssl_context:
            serve_kwargs['ssl'] = self.ssl_context
        
        async with websockets.serve(connection_handler, **serve_kwargs):
            if wait_for_shutdown:
                await self._shutdown_event.wait()
            else:
                await asyncio.Future()
    
    async def serve(self, host: str = "localhost", port: int = 8000) -> None:
        self.host = host
        self.port = port
        
        if self.is_ssl_enabled:
            logger.info(f"Starting secure WebSocket server on {self.protocol}://{host}:{port}")
            if self._ssl_cert_files:
                validation = self.validate_ssl_certificate()
                if validation.get('valid'):
                    logger.info(f"SSL certificate validated - IPv6: {validation.get('has_ipv6', False)}, SAN: {validation.get('has_san', False)}")
                else:
                    logger.warning(f"SSL certificate validation failed: {validation.get('error')}")
        else:
            logger.warning(f"Starting WebSocket server on {self.protocol}://{host}:{port} (UNENCRYPTED)")
            if self.is_production:
                logger.error("CRITICAL: Running without SSL in production environment!")
        
        await self._run_server_with_shutdown(host, port) 