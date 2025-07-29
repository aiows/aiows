"""
Settings and configuration profiles for aiows framework
"""

import os
import secrets
import logging
from typing import Dict, Any, Optional
from .config import (
    BaseConfig, ConfigValue, ConfigValidationError,
    positive_int, positive_number, valid_port, 
    valid_host, valid_log_level, min_length, 
)


class ServerConfig(BaseConfig):
    """Server configuration settings"""
    
    host = ConfigValue(
        default="localhost",
        validator=valid_host,
        type_cast=str,
        description="Host address to bind the WebSocket server"
    )
    
    port = ConfigValue(
        default=8000,
        validator=valid_port,
        type_cast=int,
        description="Port number for the WebSocket server"
    )
    
    is_production = ConfigValue(
        default=False,
        type_cast=bool,
        description="Whether the server is running in production mode"
    )
    
    require_ssl_in_production = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to require SSL in production environment"
    )
    
    ssl_cert_file = ConfigValue(
        default=None,
        type_cast=str,
        description="Path to SSL certificate file",
        sensitive=True
    )
    
    ssl_key_file = ConfigValue(
        default=None,
        type_cast=str,
        description="Path to SSL private key file",
        sensitive=True
    )
    
    ssl_cert_common_name = ConfigValue(
        default="localhost",
        type_cast=str,
        description="Common name for self-signed certificates"
    )
    
    ssl_cert_org_name = ConfigValue(
        default="aiows Development",
        type_cast=str,
        description="Organization name for self-signed certificates"
    )
    
    ssl_cert_country = ConfigValue(
        default="US",
        type_cast=str,
        description="Country code for self-signed certificates"
    )
    
    ssl_cert_days = ConfigValue(
        default=365,
        validator=positive_int,
        type_cast=int,
        description="Validity period in days for self-signed certificates"
    )
    
    shutdown_timeout = ConfigValue(
        default=30.0,
        validator=positive_number,
        type_cast=float,
        description="Timeout in seconds for graceful shutdown"
    )
    
    cleanup_interval = ConfigValue(
        default=30.0,
        validator=positive_number,
        type_cast=float,
        description="Interval in seconds for periodic cleanup tasks"
    )
    
    max_message_size = ConfigValue(
        default=1048576,  # 1MB
        validator=positive_int,
        type_cast=int,
        description="Maximum message size in bytes"
    )
    
    ping_interval = ConfigValue(
        default=20.0,
        validator=positive_number,
        type_cast=float,
        description="WebSocket ping interval in seconds"
    )
    
    ping_timeout = ConfigValue(
        default=20.0,
        validator=positive_number,
        type_cast=float,
        description="WebSocket ping timeout in seconds"
    )


class RateLimitConfig(BaseConfig):
    """Rate limiting configuration settings"""
    
    enabled = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether rate limiting is enabled"
    )
    
    max_messages_per_minute = ConfigValue(
        default=60,
        validator=positive_int,
        type_cast=int,
        description="Maximum messages per minute per client"
    )
    
    window_duration = ConfigValue(
        default=60,
        validator=positive_int,
        type_cast=int,
        description="Rate limiting window duration in seconds"
    )
    
    cleanup_interval = ConfigValue(
        default=300,
        validator=positive_number,
        type_cast=float,
        description="Cleanup interval for expired rate limit data"
    )
    
    burst_limit = ConfigValue(
        default=10,
        validator=positive_int,
        type_cast=int,
        description="Burst limit for rapid message sending"
    )


class ConnectionLimiterConfig(BaseConfig):
    """Connection limiting configuration settings"""
    
    enabled = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether connection limiting is enabled"
    )
    
    max_connections_per_ip = ConfigValue(
        default=10,
        validator=positive_int,
        type_cast=int,
        description="Maximum concurrent connections per IP address"
    )
    
    max_connections_per_minute = ConfigValue(
        default=30,
        validator=positive_int,
        type_cast=int,
        description="Maximum new connections per minute per IP"
    )
    
    sliding_window_size = ConfigValue(
        default=60,
        validator=positive_int,
        type_cast=int,
        description="Sliding window size in seconds for connection rate limiting"
    )
    
    cleanup_interval = ConfigValue(
        default=300,
        validator=positive_number,
        type_cast=float,
        description="Cleanup interval for expired connection data"
    )
    
    whitelist_ips = ConfigValue(
        default=[],
        type_cast=list,
        description="Comma-separated list of whitelisted IP addresses"
    )
    
    global_max_connections = ConfigValue(
        default=1000,
        validator=positive_int,
        type_cast=int,
        description="Global maximum concurrent connections"
    )


class AuthConfig(BaseConfig):
    """Authentication configuration settings"""
    
    enabled = ConfigValue(
        default=False,
        type_cast=bool,
        description="Whether authentication is enabled"
    )
    
    secret_key = ConfigValue(
        default=None,
        validator=min_length(32),
        type_cast=str,
        description="Secret key for token signing (min 32 characters)",
        required=False,
        sensitive=True
    )
    
    token_ttl = ConfigValue(
        default=300,
        validator=positive_int,
        type_cast=int,
        description="Token time-to-live in seconds"
    )
    
    enable_ip_validation = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to validate IP addresses in tokens"
    )
    
    rate_limit_attempts = ConfigValue(
        default=5,
        validator=positive_int,
        type_cast=int,
        description="Maximum authentication attempts per IP"
    )
    
    rate_limit_window = ConfigValue(
        default=300,
        validator=positive_int,
        type_cast=int,
        description="Rate limiting window for auth attempts in seconds"
    )
    
    auth_timeout = ConfigValue(
        default=30,
        validator=positive_int,
        type_cast=int,
        description="Authentication timeout in seconds"
    )
    
    max_tickets = ConfigValue(
        default=50000,
        validator=positive_int,
        type_cast=int,
        description="Maximum number of tickets to keep in memory"
    )
    
    allowed_origins = ConfigValue(
        default=[],
        type_cast=list,
        description="Comma-separated list of allowed origins for CORS"
    )
    
    session_timeout = ConfigValue(
        default=3600,
        validator=positive_int,
        type_cast=int,
        description="Session timeout in seconds"
    )


class LoggingConfig(BaseConfig):
    """Logging configuration settings"""
    
    enabled = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether structured logging is enabled"
    )
    
    logger_name = ConfigValue(
        default="aiows",
        type_cast=str,
        description="Logger name for aiows"
    )
    
    log_level = ConfigValue(
        default="INFO",
        validator=valid_log_level,
        type_cast=str,
        description="Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    
    use_json_format = ConfigValue(
        default=False,
        type_cast=bool,
        description="Whether to use JSON format for logs"
    )
    
    enable_rate_limiting = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to enable log rate limiting"
    )
    
    max_logs_per_minute = ConfigValue(
        default=60,
        validator=positive_int,
        type_cast=int,
        description="Maximum log messages per minute"
    )
    
    max_logs_per_hour = ConfigValue(
        default=1000,
        validator=positive_int,
        type_cast=int,
        description="Maximum log messages per hour"
    )
    
    sanitize_data = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to sanitize sensitive data in logs"
    )
    
    include_message_content = ConfigValue(
        default=False,
        type_cast=bool,
        description="Whether to include message content in logs"
    )
    
    performance_threshold_ms = ConfigValue(
        default=100.0,
        validator=positive_number,
        type_cast=float,
        description="Performance warning threshold in milliseconds"
    )


class SecurityConfig(BaseConfig):
    """Security configuration settings"""
    
    max_message_size = ConfigValue(
        default=1048576,  # 1MB
        validator=positive_int,
        type_cast=int,
        description="Maximum message size in bytes"
    )
    
    max_frame_size = ConfigValue(
        default=1048576,  # 1MB
        validator=positive_int,
        type_cast=int,
        description="Maximum WebSocket frame size in bytes"
    )
    
    handshake_timeout = ConfigValue(
        default=10.0,
        validator=positive_number,
        type_cast=float,
        description="WebSocket handshake timeout in seconds"
    )
    
    close_timeout = ConfigValue(
        default=10.0,
        validator=positive_number,
        type_cast=float,
        description="WebSocket close timeout in seconds"
    )
    
    require_origin_header = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to require Origin header"
    )
    
    allowed_origins = ConfigValue(
        default=[],
        type_cast=list,
        description="Comma-separated list of allowed origins"
    )
    
    require_user_agent = ConfigValue(
        default=True,
        type_cast=bool,
        description="Whether to require User-Agent header"
    )
    
    min_user_agent_length = ConfigValue(
        default=10,
        validator=positive_int,
        type_cast=int,
        description="Minimum User-Agent header length"
    )


class AiowsSettings:
    """Main settings class that combines all configuration sections"""
    
    def __init__(self, profile: str = "development"):
        self.profile = profile
        self._configs: Dict[str, BaseConfig] = {}
        
        self.server = ServerConfig()
        self.rate_limit = RateLimitConfig()
        self.connection_limiter = ConnectionLimiterConfig()
        self.auth = AuthConfig()
        self.logging = LoggingConfig()
        self.security = SecurityConfig()
        
        self._configs = {
            'server': self.server,
            'rate_limit': self.rate_limit,
            'connection_limiter': self.connection_limiter,
            'auth': self.auth,
            'logging': self.logging,
            'security': self.security
        }
        
        self._apply_profile(profile)
        self._post_configuration_validation()
    
    def _apply_profile(self, profile: str) -> None:
        if profile == "production":
            self._apply_production_profile()
        elif profile == "development":
            self._apply_development_profile()
        elif profile == "testing":
            self._apply_testing_profile()
        else:
            raise ConfigValidationError(f"Unknown profile: {profile}")
    
    def _apply_production_profile(self) -> None:
        self.server.is_production = True
        self.server.require_ssl_in_production = True
        if not os.getenv('AIOWS_HOST'):
            self.server.host = "0.0.0.0"
        
        self.logging.log_level = "WARNING"
        self.logging.use_json_format = True
        self.logging.sanitize_data = True
        self.logging.include_message_content = False
        
        self.security.require_origin_header = True
        self.security.require_user_agent = True
        
        if not os.getenv('AIOWS_MAX_MESSAGES_PER_MINUTE'):
            self.rate_limit.max_messages_per_minute = 30
        if not os.getenv('AIOWS_BURST_LIMIT'):
            self.rate_limit.burst_limit = 5
        
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_IP'):
            self.connection_limiter.max_connections_per_ip = 5
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_MINUTE'):
            self.connection_limiter.max_connections_per_minute = 15
        if not os.getenv('AIOWS_GLOBAL_MAX_CONNECTIONS'):
            self.connection_limiter.global_max_connections = 500
        
        if not self.auth.secret_key:
            self.auth.secret_key = secrets.token_urlsafe(64)
        self.auth.enable_ip_validation = True
        self.auth.session_timeout = 1800  # 30 minutes
    
    def _apply_development_profile(self) -> None:
        self.server.is_production = False
        self.server.require_ssl_in_production = False
        if not os.getenv('AIOWS_HOST'):
            self.server.host = "localhost"
        if not os.getenv('AIOWS_PORT'):
            self.server.port = 8000
        
        self.logging.log_level = "DEBUG"
        self.logging.use_json_format = False
        self.logging.sanitize_data = False
        self.logging.include_message_content = True
        self.logging.performance_threshold_ms = 50.0
        
        self.security.require_origin_header = False
        self.security.require_user_agent = False
        
        if not os.getenv('AIOWS_MAX_MESSAGES_PER_MINUTE'):
            self.rate_limit.max_messages_per_minute = 120
        if not os.getenv('AIOWS_BURST_LIMIT'):
            self.rate_limit.burst_limit = 20
        
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_IP'):
            self.connection_limiter.max_connections_per_ip = 20
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_MINUTE'):
            self.connection_limiter.max_connections_per_minute = 60
        if not os.getenv('AIOWS_GLOBAL_MAX_CONNECTIONS'):
            self.connection_limiter.global_max_connections = 2000
        
        if not self.auth.secret_key and self.auth.enabled:
            self.auth.secret_key = "development_key_change_in_production_" + secrets.token_urlsafe(32)
        self.auth.enable_ip_validation = False
        self.auth.session_timeout = 7200  # 2 hours
    
    def _apply_testing_profile(self) -> None:
        self.server.is_production = False
        self.server.require_ssl_in_production = False
        if not os.getenv('AIOWS_HOST'):
            self.server.host = "127.0.0.1"
        if not os.getenv('AIOWS_PORT'):
            self.server.port = 8001
        self.server.shutdown_timeout = 5.0
        self.server.cleanup_interval = 1.0
        
        self.logging.log_level = "ERROR"
        self.logging.use_json_format = False
        self.logging.sanitize_data = False
        self.logging.include_message_content = False
        self.logging.enable_rate_limiting = False
        
        self.security.require_origin_header = False
        self.security.require_user_agent = False
        self.security.handshake_timeout = 1.0
        self.security.close_timeout = 1.0
        
        if not os.getenv('AIOWS_MAX_MESSAGES_PER_MINUTE'):
            self.rate_limit.max_messages_per_minute = 1000
        if not os.getenv('AIOWS_WINDOW_DURATION'):
            self.rate_limit.window_duration = 10
        if not os.getenv('AIOWS_CLEANUP_INTERVAL'):
            self.rate_limit.cleanup_interval = 10
        
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_IP'):
            self.connection_limiter.max_connections_per_ip = 100
        if not os.getenv('AIOWS_MAX_CONNECTIONS_PER_MINUTE'):
            self.connection_limiter.max_connections_per_minute = 1000
        if not os.getenv('AIOWS_SLIDING_WINDOW_SIZE'):
            self.connection_limiter.sliding_window_size = 10
        if not os.getenv('AIOWS_CLEANUP_INTERVAL'):
            self.connection_limiter.cleanup_interval = 10
        if not os.getenv('AIOWS_GLOBAL_MAX_CONNECTIONS'):
            self.connection_limiter.global_max_connections = 10000
        
        if not self.auth.secret_key and self.auth.enabled:
            self.auth.secret_key = "testing_key_" + secrets.token_urlsafe(32)
        self.auth.token_ttl = 60
        self.auth.auth_timeout = 5
        self.auth.max_tickets = 1000
        self.auth.session_timeout = 300  # 5 minutes
    
    def _post_configuration_validation(self) -> None:
        if self.server.is_production and self.server.require_ssl_in_production:
            if not self.server.ssl_cert_file or not self.server.ssl_key_file:
                if self.profile != "testing":
                    logging.warning(
                        "Production mode requires SSL certificates. "
                        "Either provide ssl_cert_file and ssl_key_file or "
                        "set require_ssl_in_production=False"
                    )
        
        if self.auth.enabled and not self.auth.secret_key:
            raise ConfigValidationError(
                "Authentication is enabled but no secret_key provided. "
                "Set AIOWS_SECRET_KEY environment variable or provide secret_key."
            )
        
        if self.server.is_production:
            if not self.security.require_origin_header:
                logging.warning("Production mode should require Origin header for security")
            
            if not self.logging.sanitize_data:
                logging.warning("Production mode should sanitize log data for security")
    
    def reload(self) -> None:
        for config in self._configs.values():
            config.reload()
        
        self._apply_profile(self.profile)
        self._post_configuration_validation()
    
    def get_config_info(self) -> Dict[str, Any]:
        info = {
            'profile': self.profile,
            'configs': {}
        }
        
        for name, config in self._configs.items():
            info['configs'][name] = config.get_config_info()
        
        return info
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        result = {'profile': self.profile}
        
        for name, config in self._configs.items():
            result[name] = config.to_dict(include_sensitive=include_sensitive)
        
        return result
    
    def export_env_template(self, file_path: Optional[str] = None) -> str:
        from pathlib import Path
        
        lines = [
            "# aiows Framework Configuration",
            f"# Profile: {self.profile}",
            f"# Generated at: {logging.Formatter().formatTime(logging.LogRecord('', 0, '', 0, '', (), None))}",
            "",
            "# Set the configuration profile",
            f"AIOWS_PROFILE={self.profile}",
            "",
        ]
        
        for section_name, config in self._configs.items():
            lines.append(f"# === {section_name.upper()} CONFIGURATION ===")
            template = config.export_env_template()
            config_lines = template.split('\n')[4:]
            lines.extend(config_lines)
            lines.append("")
        
        template = "\n".join(lines)
        
        if file_path:
            Path(file_path).write_text(template)
            logging.info(f"Complete environment template exported to {file_path}")
        
        return template


def create_settings(profile: Optional[str] = None) -> AiowsSettings:
    if profile is None:
        profile = os.getenv('AIOWS_PROFILE', 'development')
    
    return AiowsSettings(profile=profile)


settings = create_settings() 