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
import weakref
import websockets
from typing import Dict, List, Optional, Union
from .router import Router
from .dispatcher import MessageDispatcher
from .websocket import WebSocket
from .middleware.base import BaseMiddleware

logger = logging.getLogger(__name__)


class CertificateManager:
    """Simple certificate manager for SSL/TLS support"""
    
    _temp_files = []
    
    @classmethod
    def cleanup_temp_files(cls):
        """Clean up temporary certificate files"""
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
        """Generate self-signed certificate using OpenSSL
        
        Returns:
            Tuple of (cert_file_path, key_file_path)
        """
        # Create temporary files
        cert_file = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        key_file = tempfile.NamedTemporaryFile(suffix='.key', delete=False)
        cert_file.close()
        key_file.close()
        
        # Track for cleanup
        cls._temp_files.extend([cert_file.name, key_file.name])
        
        try:
            # Generate certificate with OpenSSL
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
            # Clean up on failure
            try:
                os.unlink(cert_file.name)
                os.unlink(key_file.name)
            except:
                pass
            raise RuntimeError(f"OpenSSL not available or timed out: {e}")
    
    @classmethod
    def create_secure_ssl_context(cls, cert_file: str, key_file: str) -> ssl.SSLContext:
        """Create securely configured SSL context"""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        # Load certificate and key
        context.load_cert_chain(cert_file, key_file)
        
        # Secure configuration
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.check_hostname = False  # Self-signed certs
        context.verify_mode = ssl.CERT_NONE  # Development mode
        
        return context
    
    @classmethod
    def validate_certificate(cls, cert_file: str) -> Dict[str, Union[str, bool]]:
        """Validate certificate file and return info"""
        try:
            cmd = ['openssl', 'x509', '-in', cert_file, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {'valid': False, 'error': 'Invalid certificate format'}
            
            # Extract basic info
            output = result.stdout
            return {
                'valid': True,
                'has_san': 'Subject Alternative Name' in output,
                'has_ipv6': ':::1' in output or 'IP Address:0:0:0:0:0:0:0:1' in output,
                'subject': 'CN=' in output
            }
        except Exception as e:
            return {'valid': False, 'error': str(e)}


# Register cleanup on exit
atexit.register(CertificateManager.cleanup_temp_files)


class WebSocketServer:
    """Main WebSocket server class for aiows framework with SSL/TLS support"""
    
    def __init__(self, 
                 ssl_context: Optional[ssl.SSLContext] = None,
                 is_production: bool = False,
                 require_ssl_in_production: bool = True,
                 cert_config: Optional[Dict[str, str]] = None):
        """Initialize WebSocket server
        
        Args:
            ssl_context: SSL context for secure connections (None = no SSL)
            is_production: Whether running in production environment
            require_ssl_in_production: Whether to require SSL in production
            cert_config: Certificate configuration (common_name, org_name, country)
        """
        self.host: str = "localhost"
        self.port: int = 8000
        self.router: Router = Router()
        self.dispatcher: MessageDispatcher = MessageDispatcher(self.router)
        
        # Use WeakSet for automatic cleanup of dead connections
        self._connections: weakref.WeakSet = weakref.WeakSet()
        # Track connection count for monitoring
        self._connection_count: int = 0
        self._total_connections: int = 0
        self._cleanup_task: Optional[asyncio.Task] = None
        self._cleanup_interval: float = 30.0  # seconds
        
        self._middleware: List[BaseMiddleware] = []
        
        # SSL configuration
        self.ssl_context = ssl_context
        self.is_production = is_production
        self.require_ssl_in_production = require_ssl_in_production
        self.cert_config = cert_config or {}
        self._ssl_cert_files: Optional[tuple[str, str]] = None
        
        # Graceful shutdown configuration
        self._shutdown_event: asyncio.Event = asyncio.Event()
        self._server_task: Optional[asyncio.Task] = None
        self._shutdown_timeout: float = 30.0  # seconds
        self._signal_handlers_registered: bool = False
        
        # Validate SSL requirements
        self._validate_ssl_configuration()
    
    def get_active_connections_count(self) -> int:
        """Get current number of active connections"""
        return len(self._connections)
    
    def get_total_connections_count(self) -> int:
        """Get total number of connections since server start"""
        return self._total_connections
    
    def get_connection_stats(self) -> Dict[str, int]:
        """Get comprehensive connection statistics"""
        return {
            'active_connections': len(self._connections),
            'total_connections': self._total_connections,
            'connection_count_tracked': self._connection_count
        }
    
    async def _start_periodic_cleanup(self) -> None:
        """Start periodic cleanup task for orphaned connections"""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup_loop())
            logger.debug("Started periodic connection cleanup task")
    
    async def _stop_periodic_cleanup(self) -> None:
        """Stop periodic cleanup task"""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            logger.debug("Stopped periodic connection cleanup task")
    
    async def _periodic_cleanup_loop(self) -> None:
        """Periodic cleanup loop for orphaned connections"""
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(self._cleanup_interval)
                if self._shutdown_event.is_set():
                    break
                await self._cleanup_orphaned_connections()
        except asyncio.CancelledError:
            logger.debug("Periodic cleanup task cancelled")
        except Exception as e:
            logger.warning(f"Error in periodic cleanup: {e}")
    
    async def _cleanup_orphaned_connections(self) -> None:
        """Clean up orphaned connections that are closed but still tracked"""
        try:
            # Get snapshot of connections to avoid modification during iteration
            connections_snapshot = list(self._connections)
            orphaned_count = 0
            
            for ws in connections_snapshot:
                try:
                    if hasattr(ws, 'closed') and ws.closed:
                        # Connection is closed, remove from WeakSet explicitly
                        # WeakSet should handle this automatically, but explicit removal is safer
                        if ws in self._connections:
                            self._connections.discard(ws)
                            orphaned_count += 1
                            self._connection_count = max(0, self._connection_count - 1)
                except Exception as e:
                    logger.debug(f"Error checking connection state: {e}")
                    # Remove problematic connection
                    try:
                        self._connections.discard(ws)
                        orphaned_count += 1
                        self._connection_count = max(0, self._connection_count - 1)
                    except Exception:
                        pass
            
            if orphaned_count > 0:
                logger.debug(f"Cleaned up {orphaned_count} orphaned connections")
                
        except Exception as e:
            logger.warning(f"Error during orphaned connection cleanup: {e}")
    
    def _add_connection(self, ws: WebSocket) -> None:
        """Add connection with proper tracking"""
        try:
            self._connections.add(ws)
            self._connection_count += 1
            self._total_connections += 1
            logger.debug(f"Added connection, active: {len(self._connections)}, total: {self._total_connections}")
        except Exception as e:
            logger.warning(f"Error adding connection: {e}")
    
    def _remove_connection(self, ws: WebSocket) -> None:
        """Remove connection with proper tracking"""
        try:
            if ws in self._connections:
                self._connections.discard(ws)
                self._connection_count = max(0, self._connection_count - 1)
                logger.debug(f"Removed connection, active: {len(self._connections)}")
        except Exception as e:
            logger.warning(f"Error removing connection: {e}")
    
    def _validate_ssl_configuration(self) -> None:
        """Validate SSL configuration based on environment"""
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
        """Create SSL context for development with self-signed certificate
        
        Args:
            cert_file: Path to certificate file (will create if None)
            key_file: Path to private key file (will create if None)
            
        Returns:
            SSL context configured for development
        """
        try:
            if cert_file is None or key_file is None:
                # Generate self-signed certificate with configurable settings
                cert_file, key_file = CertificateManager.generate_self_signed_cert(
                    common_name=self.cert_config.get('common_name', 'localhost'),
                    org_name=self.cert_config.get('org_name', 'aiows Development'),
                    country=self.cert_config.get('country', 'US'),
                    days=self.cert_config.get('days', 365)
                )
                self._ssl_cert_files = (cert_file, key_file)
            
            # Create secure SSL context
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
        """Enable SSL with automatically generated self-signed certificate"""
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
        """Check if SSL is enabled"""
        return self.ssl_context is not None
    
    @property  
    def protocol(self) -> str:
        """Get protocol string (ws:// or wss://)"""
        return "wss" if self.is_ssl_enabled else "ws"
    
    def validate_ssl_certificate(self) -> Dict[str, Union[str, bool]]:
        """Validate current SSL certificate configuration
        
        Returns:
            Dictionary with validation results
        """
        if not self.is_ssl_enabled:
            return {'valid': False, 'error': 'SSL not enabled'}
        
        if not self._ssl_cert_files:
            return {'valid': False, 'error': 'No certificate files tracked'}
        
        cert_file, _ = self._ssl_cert_files
        return CertificateManager.validate_certificate(cert_file)
    
    def reload_ssl_certificate(self, cert_file: str, key_file: str) -> bool:
        """Hot reload SSL certificate for production use
        
        Args:
            cert_file: Path to new certificate file
            key_file: Path to new private key file
            
        Returns:
            True if reload successful, False otherwise
        """
        try:
            # Validate new certificate first
            validation = CertificateManager.validate_certificate(cert_file)
            if not validation.get('valid', False):
                logger.error(f"Certificate validation failed: {validation.get('error')}")
                return False
            
            # Create new SSL context
            new_context = CertificateManager.create_secure_ssl_context(cert_file, key_file)
            
            # Replace current context
            old_context = self.ssl_context
            self.ssl_context = new_context
            self._ssl_cert_files = (cert_file, key_file)
            
            logger.info(f"SSL certificate reloaded successfully from {cert_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to reload SSL certificate: {e}")
            return False
    
    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        if self._signal_handlers_registered:
            return
        
        try:
            # Register signal handlers
            loop = asyncio.get_running_loop()
            
            # SIGTERM handler
            def sigterm_handler():
                logger.info("Received SIGTERM, initiating graceful shutdown...")
                asyncio.create_task(self.shutdown())
            
            # SIGINT handler (Ctrl+C)
            def sigint_handler():
                logger.info("Received SIGINT (Ctrl+C), initiating graceful shutdown...")
                asyncio.create_task(self.shutdown())
            
            # Add signal handlers
            loop.add_signal_handler(signal.SIGTERM, sigterm_handler)
            loop.add_signal_handler(signal.SIGINT, sigint_handler)
            
            self._signal_handlers_registered = True
            logger.debug("Signal handlers registered for graceful shutdown")
            
        except Exception as e:
            logger.warning(f"Could not register signal handlers: {e}")
    
    async def shutdown(self, timeout: Optional[float] = None) -> None:
        """Initiate graceful shutdown of the server
        
        Args:
            timeout: Maximum time to wait for shutdown (uses default if None)
        """
        if self._shutdown_event.is_set():
            logger.debug("Shutdown already in progress")
            return
        
        shutdown_timeout = timeout or self._shutdown_timeout
        logger.info(f"Starting graceful shutdown (timeout: {shutdown_timeout}s)")
        
        # Signal shutdown to all tasks
        self._shutdown_event.set()
        
        # Stop periodic cleanup
        await self._stop_periodic_cleanup()
        
        # Close all active connections gracefully
        await self._close_all_connections(shutdown_timeout / 2)
        
        # Cancel server task if running
        if self._server_task and not self._server_task.done():
            self._server_task.cancel()
            try:
                await asyncio.wait_for(self._server_task, timeout=shutdown_timeout / 4)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                logger.debug("Server task cancelled or timed out")
        
        # Cleanup resources
        await self._cleanup_resources()
        
        logger.info("Graceful shutdown completed")
    
    async def _close_all_connections(self, timeout: float) -> None:
        """Close all active WebSocket connections gracefully
        
        Args:
            timeout: Maximum time to wait for connections to close
        """
        if not self._connections:
            return
        
        logger.info(f"Closing {len(self._connections)} active connections...")
        start_time = time.time()
        
        # Send close frames to all connections
        close_tasks = []
        connections_snapshot = list(self._connections)  # Create snapshot to avoid modification during iteration
        
        for ws in connections_snapshot:
            try:
                if not ws.closed:
                    task = asyncio.create_task(self._close_connection_gracefully(ws))
                    close_tasks.append(task)
            except Exception as e:
                logger.debug(f"Error initiating close for connection: {e}")
                # Remove problematic connection immediately
                self._remove_connection(ws)
        
        # Wait for connections to close with timeout
        if close_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*close_tasks, return_exceptions=True),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                elapsed = time.time() - start_time
                logger.warning(f"Connection close timeout after {elapsed:.1f}s, forcing closure")
                
                # Force close remaining connections without waiting
                remaining_connections = list(self._connections)
                for ws in remaining_connections:
                    try:
                        if not ws.closed:
                            # Create task for force close but don't wait for it
                            asyncio.create_task(ws.close(code=1001, reason="Server shutdown"))
                        # Remove from connections immediately
                        self._remove_connection(ws)
                    except Exception as e:
                        logger.debug(f"Error force-closing connection: {e}")
                        self._remove_connection(ws)
        
        # Wait a bit more for connections to be removed from set
        for _ in range(10):  # Max 1 second
            if not self._connections:
                break
            await asyncio.sleep(0.1)
        
        remaining = len(self._connections)
        if remaining > 0:
            logger.warning(f"{remaining} connections did not close gracefully")
            # Force clear remaining connections
            self._connections.clear()
            self._connection_count = 0
        else:
            logger.info("All connections closed successfully")
    
    async def _close_connection_gracefully(self, ws: WebSocket) -> None:
        """Close a single WebSocket connection gracefully
        
        Args:
            ws: WebSocket connection to close
        """
        try:
            # Dispatch disconnect event first
            await self.dispatcher.dispatch_disconnect(ws, "Server shutdown")
        except Exception as e:
            logger.debug(f"Error in disconnect handler: {e}")
        
        try:
            # Close the connection
            if not ws.closed:
                await ws.close(code=1001, reason="Server shutdown")
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")
        finally:
            # Always remove from connections set, even if close failed
            self._remove_connection(ws)
    
    async def _cleanup_resources(self) -> None:
        """Cleanup server resources"""
        try:
            # Final connection cleanup
            await self._cleanup_orphaned_connections()
            
            # Clear connections set
            self._connections.clear()
            self._connection_count = 0
            
            # Clean up temporary SSL files if they exist
            if hasattr(CertificateManager, 'cleanup_temp_files'):
                CertificateManager.cleanup_temp_files()
            
            logger.debug("Resource cleanup completed")
            
        except Exception as e:
            logger.warning(f"Error during resource cleanup: {e}")
    
    def set_shutdown_timeout(self, timeout: float) -> None:
        """Set the timeout for graceful shutdown
        
        Args:
            timeout: Timeout in seconds
        """
        if timeout <= 0:
            raise ValueError("Shutdown timeout must be positive")
        self._shutdown_timeout = timeout
        logger.debug(f"Shutdown timeout set to {timeout}s")
    
    @property
    def is_shutting_down(self) -> bool:
        """Check if server is in shutdown process"""
        return self._shutdown_event.is_set()
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        """Add global middleware to the server
        
        Args:
            middleware: Middleware instance to add
        """
        self._middleware.append(middleware)
        # Update dispatcher with new middleware
        self._update_dispatcher_middleware()
    
    def _update_dispatcher_middleware(self) -> None:
        """Update dispatcher with combined middleware from server and router"""
        # Clear existing middleware
        self.dispatcher._middleware.clear()
        
        # Add server middleware first (they execute first)
        for middleware in self._middleware:
            self.dispatcher.add_middleware(middleware)
        
        # Add router middleware (they execute after server middleware)
        for middleware in self.router.get_all_middleware():
            self.dispatcher.add_middleware(middleware)
    
    def include_router(self, router: Router) -> None:
        """Include router to the server
        
        Args:
            router: Router instance to include
        """
        self.router = router
        self.dispatcher = MessageDispatcher(self.router)
        # Apply all middleware to new dispatcher
        self._update_dispatcher_middleware()
    
    async def _handle_connection(self, websocket) -> None:
        """Handle single WebSocket connection
        
        Args:
            websocket: Raw websocket connection (ServerConnection)
        """
        # Create WebSocket wrapper
        ws_wrapper = WebSocket(websocket)
        connection_added = False
        
        try:
            # Add to active connections with proper tracking
            self._add_connection(ws_wrapper)
            connection_added = True
            
            # Call dispatch_connect
            await self.dispatcher.dispatch_connect(ws_wrapper)
            
            # Message processing loop with shutdown check
            while not ws_wrapper.closed and not self._shutdown_event.is_set():
                try:
                    # Check for shutdown during receive with timeout
                    try:
                        message_data = await asyncio.wait_for(
                            ws_wrapper.receive_json(),
                            timeout=1.0  # Check shutdown every second
                        )
                        await self.dispatcher.dispatch_message(ws_wrapper, message_data)
                    except asyncio.TimeoutError:
                        # Timeout is normal, just continue to check shutdown
                        continue
                        
                except Exception as e:
                    # Check if this is a shutdown-related close
                    if self._shutdown_event.is_set():
                        logger.debug("Connection closed during shutdown")
                        break
                    
                    # Don't log normal connection closures (code 1000)
                    if "1000 (OK)" not in str(e) and "1001" not in str(e):
                        logger.debug(f"Error processing message: {str(e)}")
                    break
                    
        except Exception as e:
            if not self._shutdown_event.is_set():
                logger.debug(f"Connection error: {str(e)}")
        finally:
            # Comprehensive cleanup in finally block
            cleanup_error = None
            
            # Handle disconnection (only if not already handled by graceful close)
            if connection_added and ws_wrapper in self._connections:
                reason = "Server shutdown" if self._shutdown_event.is_set() else "Connection closed"
                try:
                    await self.dispatcher.dispatch_disconnect(ws_wrapper, reason)
                except Exception as e:
                    cleanup_error = e
                    logger.debug(f"Error in disconnect handler: {str(e)}")
            
            # Always remove from connections, even if dispatch_disconnect failed
            if connection_added:
                try:
                    self._remove_connection(ws_wrapper)
                except Exception as e:
                    if cleanup_error is None:
                        cleanup_error = e
                    logger.debug(f"Error removing connection: {str(e)}")
            
            # Ensure connection is closed
            if not ws_wrapper.closed:
                try:
                    close_code = 1001 if self._shutdown_event.is_set() else 1000
                    await ws_wrapper.close(code=close_code)
                except Exception as e:
                    if cleanup_error is None:
                        cleanup_error = e
                    logger.debug(f"Error closing connection: {str(e)}")
            
            # Log any cleanup errors (but don't raise them)
            if cleanup_error:
                logger.debug(f"Connection cleanup completed with errors: {cleanup_error}")
    
    def run(self, host: str = "localhost", port: int = 8000) -> None:
        """Start WebSocket server
        
        Args:
            host: Server host (default: localhost)
            port: Server port (default: 8000)
        """
        self.host = host
        self.port = port
        
        # Log security status
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
        """Run WebSocket server with graceful shutdown support"""
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Reset shutdown event for new run
        self._shutdown_event.clear()
        
        # Start periodic cleanup
        await self._start_periodic_cleanup()
        
        try:
            # Start the server with shutdown support
            self._server_task = asyncio.create_task(self._run_server(host, port, wait_for_shutdown=True))
            
            # Wait for either server completion or shutdown signal
            done, pending = await asyncio.wait(
                [self._server_task, asyncio.create_task(self._shutdown_event.wait())],
                return_when=asyncio.FIRST_COMPLETED
            )
            
            # If shutdown was triggered, initiate graceful shutdown
            if self._shutdown_event.is_set():
                logger.info("Shutdown event triggered, starting graceful shutdown...")
                await self.shutdown()
            
            # Cancel any remaining tasks
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
            # Ensure cleanup even if something goes wrong
            await self._stop_periodic_cleanup()
            if not self._shutdown_event.is_set():
                await self._cleanup_resources()

    async def _run_server(self, host: str, port: int, wait_for_shutdown: bool = True) -> None:
        """Internal method to run the WebSocket server
        
        Args:
            host: Server host
            port: Server port  
            wait_for_shutdown: If True, wait for shutdown event. If False, run forever (for tests)
        """
        # Create wrapper function that properly handles the websockets.serve callback
        async def connection_handler(websocket):
            await self._handle_connection(websocket)
        
        # Configure websockets.serve with SSL if enabled
        serve_kwargs = {
            'host': host,
            'port': port
        }
        
        if self.ssl_context:
            serve_kwargs['ssl'] = self.ssl_context
        
        async with websockets.serve(connection_handler, **serve_kwargs):
            if wait_for_shutdown:
                # Wait for shutdown event (graceful shutdown mode)
                await self._shutdown_event.wait()
            else:
                # Run forever (compatibility mode for tests)
                await asyncio.Future()
    
    async def serve(self, host: str = "localhost", port: int = 8000) -> None:
        """Async version of run() for use in existing async contexts
        
        Args:
            host: Server host (default: localhost)  
            port: Server port (default: 8000)
        """
        self.host = host
        self.port = port
        
        # Log security status  
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