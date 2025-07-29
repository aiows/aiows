"""
Secure logging middleware for aiows framework with structured logging, correlation IDs, and data sanitization
"""

import time
import json
import logging
import uuid
import re
import hashlib
from collections import deque
from typing import Any, Awaitable, Callable, Optional, Dict, Union, TYPE_CHECKING
from datetime import datetime, timedelta, timezone
from .base import BaseMiddleware
from ..websocket import WebSocket

if TYPE_CHECKING:
    from ..settings import LoggingConfig


class SecureJSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging with security features"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        if hasattr(record, 'correlation_id'):
            log_entry['correlation_id'] = record.correlation_id
        
        if hasattr(record, 'structured_data'):
            log_entry.update(record.structured_data)
        
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str, ensure_ascii=False)


class LogRateLimiter:
    """Rate limiter for log messages to prevent log flooding"""
    
    def __init__(self, max_logs_per_minute: int = 60, max_logs_per_hour: int = 1000):
        self.max_logs_per_minute = max_logs_per_minute
        self.max_logs_per_hour = max_logs_per_hour
        self.minute_logs = deque()
        self.hour_logs = deque()
        self.last_cleanup = datetime.now()
    
    def _cleanup_old_logs(self):
        now = datetime.now()
        
        if (now - self.last_cleanup).seconds < 10:
            return
        
        self.last_cleanup = now
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        while self.minute_logs and self.minute_logs[0] < minute_ago:
            self.minute_logs.popleft()
        
        while self.hour_logs and self.hour_logs[0] < hour_ago:
            self.hour_logs.popleft()
    
    def is_allowed(self) -> bool:
        self._cleanup_old_logs()
        
        if len(self.minute_logs) >= self.max_logs_per_minute:
            return False
        
        if len(self.hour_logs) >= self.max_logs_per_hour:
            return False
        
        now = datetime.now()
        self.minute_logs.append(now)
        self.hour_logs.append(now)
        
        return True


class DataSanitizer:
    """Utility class for sanitizing sensitive data from logs"""
    
    SENSITIVE_PATTERNS = {
        'password': re.compile(r'password["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', re.IGNORECASE),
        'token': re.compile(r'\btoken\s+([A-Za-z0-9_\-\.]+)', re.IGNORECASE),
        'api_key': re.compile(r'api[_-]?key["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', re.IGNORECASE),
        'secret': re.compile(r'secret["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', re.IGNORECASE),
        'authorization': re.compile(r'authorization["\']?\s*[:=]\s*["\']?([^"\'}\s,]+)', re.IGNORECASE),
        'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
    }
    
    SENSITIVE_KEYS = {
        'password', 'passwd', 'pass', 'secret', 'token', 'key', 'api_key', 'apikey',
        'authorization', 'auth', 'credential', 'cred', 'private_key', 'privatekey',
        'access_token', 'refresh_token', 'session_id', 'sessionid', 'cookie',
        'ssn', 'social_security_number', 'credit_card', 'creditcard', 'cvv', 'pin'
    }
    
    @staticmethod
    def mask_value(value: str, mask_char: str = '*', keep_chars: int = 2) -> str:
        if len(value) <= keep_chars * 2:
            return mask_char * len(value)
        
        middle_length = len(value) - (keep_chars * 2)
        return value[:keep_chars] + mask_char * middle_length + value[-keep_chars:]
    
    @staticmethod
    def hash_value(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()[:8]
    
    @classmethod
    def sanitize_string(cls, text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        
        for pattern_name, pattern in cls.SENSITIVE_PATTERNS.items():
            def mask_match(match):
                sensitive_value = match.group(1) if match.groups() else match.group(0)
                if pattern_name in ['email', 'phone']:
                    return match.group(0).replace(sensitive_value, cls.hash_value(sensitive_value))
                else:
                    return match.group(0).replace(sensitive_value, cls.mask_value(sensitive_value))
            
            text = pattern.sub(mask_match, text)
        
        return text
    
    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
        if max_depth <= 0:
            return {"_truncated": "max_depth_reached"}
        
        if not isinstance(data, dict):
            if isinstance(data, str):
                return {"_non_dict_string": cls.sanitize_string(data)}
            else:
                return {"_non_dict_value": str(data)}
        
        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            
            is_sensitive_key = (
                key_lower in cls.SENSITIVE_KEYS or 
                any(
                    sensitive_key in key_lower and (
                        key_lower == sensitive_key or
                        key_lower == sensitive_key + 's' or
                        key_lower.endswith('_' + sensitive_key) or
                        key_lower.endswith('_' + sensitive_key + 's') or
                        key_lower.endswith(sensitive_key) or
                        key_lower.endswith(sensitive_key + 's') or
                        key_lower.startswith(sensitive_key + '_') or
                        key_lower.startswith(sensitive_key + 's_') or
                        '_' + sensitive_key + '_' in key_lower or
                        '_' + sensitive_key + 's_' in key_lower
                    )
                    for sensitive_key in cls.SENSITIVE_KEYS if len(sensitive_key) > 2
                )
            )
            
            if is_sensitive_key:
                if isinstance(value, str):
                    sanitized[key] = cls.mask_value(value)
                elif isinstance(value, (list, tuple)):
                    sanitized_list = []
                    for item in value[:10]:
                        if isinstance(item, str):
                            sanitized_list.append(cls.mask_value(item))
                        else:
                            sanitized_list.append(cls.sanitize_value(item, max_depth - 1))
                    sanitized[key] = sanitized_list
                elif isinstance(value, dict):
                    sanitized[key] = cls.sanitize_value(value, max_depth - 1)
                else:
                    sanitized[key] = cls.hash_value(str(value))
            else:
                sanitized[key] = cls.sanitize_value(value, max_depth - 1)
        
        return sanitized
    
    @classmethod
    def sanitize_value(cls, value: Any, max_depth: int = 5) -> Any:
        if max_depth <= 0:
            return {"_truncated": "max_depth_reached"} if isinstance(value, dict) else str(value)[:50]
        
        if isinstance(value, dict):
            return cls.sanitize_dict(value, max_depth)
        elif isinstance(value, (list, tuple)):
            return [cls.sanitize_value(item, max_depth - 1) for item in value[:10]]
        elif isinstance(value, str):
            return cls.sanitize_string(value)
        else:
            return value


class LoggingMiddleware(BaseMiddleware):
    """
    Secure logging middleware with structured logging, correlation IDs, and data sanitization.
    
    Features:
    - Correlation IDs for request tracing
    - Data sanitization to prevent sensitive data leakage
    - Structured JSON logging
    - Rate limiting to prevent log flooding
    - Performance monitoring
    - Configurable log levels
    """
    
    def __init__(
        self,
        logger_name: Optional[str] = None,
        use_json_format: Optional[bool] = None,
        log_level: Optional[Union[str, int]] = None,
        enable_rate_limiting: Optional[bool] = None,
        max_logs_per_minute: Optional[int] = None,
        max_logs_per_hour: Optional[int] = None,
        sanitize_data: Optional[bool] = None,
        include_message_content: Optional[bool] = None,
        performance_threshold_ms: Optional[float] = None,
        config: Optional['LoggingConfig'] = None
    ):
        # Load configuration
        if config is not None:
            logger_name = logger_name or config.logger_name
            use_json_format = use_json_format if use_json_format is not None else config.use_json_format
            log_level = log_level or config.log_level
            enable_rate_limiting = enable_rate_limiting if enable_rate_limiting is not None else config.enable_rate_limiting
            max_logs_per_minute = max_logs_per_minute or config.max_logs_per_minute
            max_logs_per_hour = max_logs_per_hour or config.max_logs_per_hour
            sanitize_data = sanitize_data if sanitize_data is not None else config.sanitize_data
            include_message_content = include_message_content if include_message_content is not None else config.include_message_content
            performance_threshold_ms = performance_threshold_ms or config.performance_threshold_ms
        else:
            # Use defaults for backward compatibility
            logger_name = logger_name or "aiows"
            use_json_format = use_json_format if use_json_format is not None else False
            log_level = log_level or logging.INFO
            enable_rate_limiting = enable_rate_limiting if enable_rate_limiting is not None else True
            max_logs_per_minute = max_logs_per_minute or 60
            max_logs_per_hour = max_logs_per_hour or 1000
            sanitize_data = sanitize_data if sanitize_data is not None else True
            include_message_content = include_message_content if include_message_content is not None else False
            performance_threshold_ms = performance_threshold_ms or 100.0
        
        self.logger = logging.getLogger(logger_name)
        self.sanitize_data = sanitize_data
        self.include_message_content = include_message_content
        self.performance_threshold_ms = performance_threshold_ms
        
        if isinstance(log_level, str):
            log_level = getattr(logging, log_level.upper())
        self.logger.setLevel(log_level)
        
        if use_json_format:
            # Create a unique logger name to avoid conflicts with other loggers
            unique_logger_name = f"{logger_name}.middleware.{id(self)}"
            self.logger = logging.getLogger(unique_logger_name)
            self.logger.setLevel(log_level)
            
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
            
            handler = logging.StreamHandler()
            handler.setFormatter(SecureJSONFormatter())
            self.logger.addHandler(handler)
            self.logger.propagate = False
        
        self.rate_limiter = LogRateLimiter(max_logs_per_minute, max_logs_per_hour) if enable_rate_limiting else None
        
        self.connection_correlations: Dict[str, str] = {}
    
    @classmethod
    def from_config(cls, config: 'LoggingConfig') -> 'LoggingMiddleware':
        """Create LoggingMiddleware instance from LoggingConfig
        
        Args:
            config: LoggingConfig instance with configuration
            
        Returns:
            Configured LoggingMiddleware instance
        """
        return cls(config=config)
    
    def _should_log(self) -> bool:
        if self.rate_limiter is None:
            return True
        return self.rate_limiter.is_allowed()
    
    def _generate_correlation_id(self) -> str:
        return str(uuid.uuid4())
    
    def _get_correlation_id(self, websocket: WebSocket) -> str:
        connection_id = id(websocket)
        
        if connection_id not in self.connection_correlations:
            self.connection_correlations[connection_id] = self._generate_correlation_id()
        
        return self.connection_correlations[connection_id]
    
    def _cleanup_correlation_id(self, websocket: WebSocket):
        connection_id = id(websocket)
        self.connection_correlations.pop(connection_id, None)
    
    def _get_client_info(self, websocket: WebSocket) -> Dict[str, Any]:
        client_info = {}
        
        try:
            if hasattr(websocket._websocket, 'remote_address'):
                ip = str(websocket._websocket.remote_address[0])
                client_info['client_ip_hash'] = DataSanitizer.hash_value(ip)
            elif hasattr(websocket._websocket, 'host'):
                ip = websocket._websocket.host
                client_info['client_ip_hash'] = DataSanitizer.hash_value(ip)
        except Exception:
            client_info['client_ip_hash'] = "unknown"
        
        user_id = websocket.context.get('user_id')
        if user_id:
            client_info['user_id_hash'] = DataSanitizer.hash_value(str(user_id))
        
        client_info['authenticated'] = bool(websocket.context.get('authenticated', False))
        
        client_info['connection_id'] = DataSanitizer.hash_value(str(id(websocket)))
        
        return client_info
    
    def _get_message_info(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        message_info = {}
        
        message_info['message_type'] = message_data.get('type', 'unknown')
        
        try:
            if self.sanitize_data:
                sanitized_data = DataSanitizer.sanitize_dict(message_data)
                message_size = len(json.dumps(sanitized_data))
            else:
                message_size = len(json.dumps(message_data))
            message_info['message_size_bytes'] = message_size
        except Exception:
            message_info['message_size_bytes'] = len(str(message_data))
        
        if self.include_message_content:
            if self.sanitize_data:
                message_info['message_content'] = DataSanitizer.sanitize_dict(message_data)
            else:
                message_info['message_content'] = message_data
        
        try:
            content_str = json.dumps(message_data, sort_keys=True)
            message_info['message_fingerprint'] = DataSanitizer.hash_value(content_str)
        except Exception:
            message_info['message_fingerprint'] = DataSanitizer.hash_value(str(message_data))
        
        return message_info
    
    def _log_structured(self, level: int, message: str, correlation_id: str, **structured_data):
        if not self._should_log():
            return
        
        extra = {
            'correlation_id': correlation_id,
            'structured_data': structured_data
        }
        
        self.logger.log(level, message, extra=extra)
    
    async def on_connect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        websocket = None
        correlation_id = None
        
        if args and isinstance(args[0], WebSocket):
            websocket = args[0]
            correlation_id = self._get_correlation_id(websocket)
            client_info = self._get_client_info(websocket)
            
            self._log_structured(
                logging.INFO,
                "WebSocket connection established",
                correlation_id,
                event_type="connection_established",
                **client_info
            )
        
        start_time = time.time()
        
        try:
            result = await handler(*args, **kwargs)
            
            if websocket and correlation_id:
                processing_time_ms = (time.time() - start_time) * 1000
                self._log_structured(
                    logging.INFO,
                    "Connection handler completed successfully",
                    correlation_id,
                    event_type="connection_processed",
                    processing_time_ms=round(processing_time_ms, 2),
                    success=True
                )
            
            return result
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            
            if websocket and correlation_id:
                client_info = self._get_client_info(websocket)
                
                self._log_structured(
                    logging.ERROR,
                    "Error during connection handling",
                    correlation_id,
                    event_type="connection_error",
                    processing_time_ms=round(processing_time_ms, 2),
                    error_type=type(e).__name__,
                    error_message=DataSanitizer.sanitize_string(str(e)),
                    success=False,
                    **client_info
                )
            raise
    
    async def on_message(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        start_time = time.time()
        websocket = None
        message_data = None
        correlation_id = None
        
        if len(args) >= 2 and isinstance(args[0], WebSocket):
            websocket = args[0]
            message_data = args[1]
            correlation_id = self._get_correlation_id(websocket)
        
        if websocket and message_data and correlation_id:
            client_info = self._get_client_info(websocket)
            message_info = self._get_message_info(message_data)
            
            self._log_structured(
                logging.INFO,
                "Message received",
                correlation_id,
                event_type="message_received",
                **client_info,
                **message_info
            )
        
        try:
            result = await handler(*args, **kwargs)
            
            processing_time_ms = (time.time() - start_time) * 1000
            
            if websocket and message_data and correlation_id:
                client_info = self._get_client_info(websocket)
                message_info = self._get_message_info(message_data)
                
                log_level = logging.WARNING if processing_time_ms > self.performance_threshold_ms else logging.INFO
                
                self._log_structured(
                    log_level,
                    "Message processed successfully",
                    correlation_id,
                    event_type="message_processed",
                    processing_time_ms=round(processing_time_ms, 2),
                    performance_warning=processing_time_ms > self.performance_threshold_ms,
                    success=True,
                    **client_info,
                    **message_info
                )
            
            return result
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            
            if websocket and message_data and correlation_id:
                client_info = self._get_client_info(websocket)
                message_info = self._get_message_info(message_data)
                
                self._log_structured(
                    logging.ERROR,
                    "Error processing message",
                    correlation_id,
                    event_type="message_error",
                    processing_time_ms=round(processing_time_ms, 2),
                    error_type=type(e).__name__,
                    error_message=DataSanitizer.sanitize_string(str(e)),
                    success=False,
                    **client_info,
                    **message_info
                )
            raise
    
    async def on_disconnect(self, handler: Callable[..., Awaitable[Any]], *args: Any, **kwargs: Any) -> Any:
        websocket = None
        reason = "unknown"
        correlation_id = None
        
        if len(args) >= 2 and isinstance(args[0], WebSocket):
            websocket = args[0]
            reason = str(args[1]) if args[1] else "unknown"
            correlation_id = self._get_correlation_id(websocket)
        
        if websocket and correlation_id:
            client_info = self._get_client_info(websocket)
            
            self._log_structured(
                logging.INFO,
                "WebSocket connection closed",
                correlation_id,
                event_type="connection_closed",
                disconnect_reason=DataSanitizer.sanitize_string(reason),
                **client_info
            )
        
        try:
            result = await handler(*args, **kwargs)
            
            if websocket:
                self._cleanup_correlation_id(websocket)
            
            return result
        except Exception as e:
            if websocket and correlation_id:
                client_info = self._get_client_info(websocket)
                
                self._log_structured(
                    logging.ERROR,
                    "Error during disconnection handling",
                    correlation_id,
                    event_type="disconnection_error",
                    error_type=type(e).__name__,
                    error_message=DataSanitizer.sanitize_string(str(e)),
                    **client_info
                )
            
            if websocket:
                self._cleanup_correlation_id(websocket)
            
            raise 
            # Cleanup correlation ID even on error
            if websocket:
                self._cleanup_correlation_id(websocket)
            
            raise 