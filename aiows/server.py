"""
WebSocket server implementation with SSL/TLS support
"""

import asyncio
import atexit
import logging
import os
import ssl
import subprocess
import tempfile
import warnings
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
        self._connections: set = set()
        self._middleware: List[BaseMiddleware] = []
        
        # SSL configuration
        self.ssl_context = ssl_context
        self.is_production = is_production
        self.require_ssl_in_production = require_ssl_in_production
        self.cert_config = cert_config or {}
        self._ssl_cert_files: Optional[tuple[str, str]] = None
        
        # Validate SSL requirements
        self._validate_ssl_configuration()
    
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
        
        # Add to active connections
        self._connections.add(ws_wrapper)
        
        try:
            # Call dispatch_connect
            await self.dispatcher.dispatch_connect(ws_wrapper)
            
            # Message processing loop
            while not ws_wrapper.closed:
                try:
                    # Receive message and dispatch
                    message_data = await ws_wrapper.receive_json()
                    await self.dispatcher.dispatch_message(ws_wrapper, message_data)
                except Exception as e:
                    # Don't log normal connection closures (code 1000)
                    if "1000 (OK)" not in str(e):
                        print(f"Error processing message: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"Connection error: {str(e)}")
        finally:
            # Handle disconnection
            reason = "Connection closed"
            try:
                await self.dispatcher.dispatch_disconnect(ws_wrapper, reason)
            except Exception as e:
                print(f"Error in disconnect handler: {str(e)}")
            
            # Remove from connections
            self._connections.discard(ws_wrapper)
            
            # Ensure connection is closed
            if not ws_wrapper.closed:
                await ws_wrapper.close()
    
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
            asyncio.run(self._run_server(host, port))
        except KeyboardInterrupt:
            logger.info("Server shutdown requested")
        except Exception as e:
            logger.error(f"Server error: {e}")
            raise
    
    async def _run_server(self, host: str, port: int) -> None:
        """Internal method to run the WebSocket server"""
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
            await asyncio.Future()  # run forever
    
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
        
        await self._run_server(host, port) 