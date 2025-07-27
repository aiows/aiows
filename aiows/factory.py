"""
Factory functions for creating aiows components from configuration
"""

from typing import List, Optional
from .server import WebSocketServer
from .settings import AiowsSettings, create_settings
from .middleware.base import BaseMiddleware
from .middleware.auth import AuthMiddleware
from .middleware.rate_limit import RateLimitingMiddleware
from .middleware.connection_limiter import ConnectionLimiterMiddleware
from .middleware.logging import LoggingMiddleware


def create_server_from_settings(settings: Optional[AiowsSettings] = None, 
                               include_middleware: bool = True) -> WebSocketServer:
    """Create WebSocketServer with automatic middleware configuration
    
    Args:
        settings: AiowsSettings instance (creates default if None)
        include_middleware: Whether to automatically add configured middleware
        
    Returns:
        Configured WebSocketServer instance
    """
    if settings is None:
        settings = create_settings()
    
    server = WebSocketServer.from_settings(settings)
    
    if include_middleware:
        middleware_list = create_middleware_from_settings(settings)
        for middleware in middleware_list:
            server.add_middleware(middleware)
    
    return server


def create_middleware_from_settings(settings: AiowsSettings) -> List[BaseMiddleware]:
    """Create list of middleware instances from settings
    
    Args:
        settings: AiowsSettings instance with configuration
        
    Returns:
        List of configured middleware instances in correct order
    """
    middleware_list = []
    
    # Order matters: Logging -> ConnectionLimiter -> Auth -> RateLimit
    if settings.logging.enabled:
        middleware_list.append(LoggingMiddleware.from_config(settings.logging))
    
    if settings.connection_limiter.enabled:
        middleware_list.append(ConnectionLimiterMiddleware.from_config(settings.connection_limiter))
    
    if settings.auth.enabled:
        middleware_list.append(AuthMiddleware.from_config(settings.auth))
    
    if settings.rate_limit.enabled:
        middleware_list.append(RateLimitingMiddleware.from_config(settings.rate_limit))
    
    return middleware_list


def create_production_server(profile: str = "production") -> WebSocketServer:
    """Create production-ready server with all security features enabled
    
    IMPORTANT: Production servers require SSL configuration!
    Either provide ssl_context when creating the server or set SSL certificate paths
    in environment variables (AIOWS_SSL_CERT_FILE, AIOWS_SSL_KEY_FILE).
    
    Args:
        profile: Configuration profile to use (default: "production")
        
    Returns:
        Production-configured WebSocketServer with all middleware
        
    Raises:
        ValueError: If SSL context is required but not provided
    """
    settings = AiowsSettings(profile=profile)
    
    if profile == "production":
        settings.auth.enabled = True
        settings.connection_limiter.enabled = True
        settings.rate_limit.enabled = True
        settings.logging.enabled = True
        settings.logging.sanitize_data = True
        settings.logging.use_json_format = True
        # SSL requirement is already correctly set to True in production profile
        # settings.server.require_ssl_in_production = True  # Already set by profile
    
    return create_server_from_settings(settings, include_middleware=True)


def create_development_server(profile: str = "development") -> WebSocketServer:
    """Create development server with relaxed security for testing
    
    Args:
        profile: Configuration profile to use (default: "development")
        
    Returns:
        Development-configured WebSocketServer
    """
    settings = AiowsSettings(profile=profile)
    
    if profile == "development":
        settings.rate_limit.max_messages_per_minute = 120
        settings.connection_limiter.max_connections_per_ip = 20
        settings.logging.log_level = "DEBUG"
        settings.logging.include_message_content = True
        settings.logging.sanitize_data = False
    
    return create_server_from_settings(settings, include_middleware=True)


def create_testing_server(profile: str = "testing") -> WebSocketServer:
    """Create testing server with minimal overhead and fast timeouts
    
    Args:
        profile: Configuration profile to use (default: "testing")
        
    Returns:
        Testing-configured WebSocketServer
    """
    settings = AiowsSettings(profile=profile)
    
    if profile == "testing":
        settings.server.shutdown_timeout = 1.0
        settings.server.cleanup_interval = 0.1
        settings.rate_limit.max_messages_per_minute = 1000
        settings.connection_limiter.max_connections_per_ip = 100
        settings.logging.log_level = "ERROR"
        settings.logging.enable_rate_limiting = False
        settings.auth.auth_timeout = 1
    
    return create_server_from_settings(settings, include_middleware=True)


def create_custom_server(host: str = None,
                        port: int = None,
                        profile: str = "development",
                        enable_auth: bool = False,
                        enable_logging: bool = True,
                        enable_rate_limit: bool = True,
                        enable_connection_limiter: bool = True) -> WebSocketServer:
    """Create server with custom configuration
    
    Args:
        host: Server host (uses profile default if None)
        port: Server port (uses profile default if None)
        profile: Base configuration profile
        enable_auth: Whether to enable authentication
        enable_logging: Whether to enable logging middleware
        enable_rate_limit: Whether to enable rate limiting
        enable_connection_limiter: Whether to enable connection limiting
        
    Returns:
        Custom-configured WebSocketServer
    """
    settings = AiowsSettings(profile=profile)
    
    if host is not None:
        settings.server.host = host
    if port is not None:
        settings.server.port = port
    
    settings.auth.enabled = enable_auth
    settings.logging.enabled = enable_logging
    settings.rate_limit.enabled = enable_rate_limit
    settings.connection_limiter.enabled = enable_connection_limiter
    
    return create_server_from_settings(settings, include_middleware=True)


def create_auth_middleware(settings: AiowsSettings) -> AuthMiddleware:
    return AuthMiddleware.from_config(settings.auth)


def create_rate_limit_middleware(settings: AiowsSettings) -> RateLimitingMiddleware:
    return RateLimitingMiddleware.from_config(settings.rate_limit)


def create_connection_limiter_middleware(settings: AiowsSettings) -> ConnectionLimiterMiddleware:
    return ConnectionLimiterMiddleware.from_config(settings.connection_limiter)


def create_logging_middleware(settings: AiowsSettings) -> LoggingMiddleware:
    return LoggingMiddleware.from_config(settings.logging)


def auto_configure_for_environment() -> WebSocketServer:
    """Automatically configure server based on environment variables
    
    Reads AIOWS_PROFILE environment variable or detects environment:
    - If AIOWS_PROFILE=production -> production server
    - If AIOWS_PROFILE=testing -> testing server
    - Default -> development server
    
    Returns:
        Auto-configured WebSocketServer
    """
    import os
    
    profile = os.getenv('AIOWS_PROFILE', 'development')
    
    if profile == "production":
        return create_production_server()
    elif profile == "testing":
        return create_testing_server()
    else:
        return create_development_server()


def quick_start_server(host: str = "localhost", 
                      port: int = 8000,
                      with_auth: bool = False) -> WebSocketServer:
    """Quick start server for rapid prototyping
    
    Args:
        host: Server host
        port: Server port  
        with_auth: Whether to enable authentication
        
    Returns:
        Ready-to-use WebSocketServer for development
    """
    return create_custom_server(
        host=host,
        port=port,
        profile="development",
        enable_auth=with_auth,
        enable_logging=True,
        enable_rate_limit=True,
        enable_connection_limiter=True
    ) 