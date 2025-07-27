"""
Tests for secure logging middleware functionality
"""

import asyncio
import json
import logging
import time
import uuid
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from aiows.middleware.logging import (
    LoggingMiddleware, 
    DataSanitizer, 
    LogRateLimiter, 
    SecureJSONFormatter
)
from aiows.websocket import WebSocket


class TestDataSanitizer:
    """Test data sanitization functionality"""
    
    def test_mask_value(self):
        """Test value masking"""
        assert DataSanitizer.mask_value("abc") == "***"
        assert DataSanitizer.mask_value("password123") == "pa*******23"
        assert DataSanitizer.mask_value("secret_key_123", keep_chars=1) == "s************3"
    
    def test_hash_value(self):
        """Test value hashing"""
        value = "test@example.com"
        hash1 = DataSanitizer.hash_value(value)
        hash2 = DataSanitizer.hash_value(value)
        assert hash1 == hash2
        assert len(hash1) == 8
        assert hash1 != value
    
    def test_sanitize_string_patterns(self):
        """Test string sanitization with various patterns"""
        text = 'user login with password="secretpass123"'
        sanitized = DataSanitizer.sanitize_string(text)
        assert "secretpass123" not in sanitized
        assert "se*********23" in sanitized
        
        text = "Authorization: Bearer token abc123def456"
        sanitized = DataSanitizer.sanitize_string(text)
        assert "abc123def456" not in sanitized
        
        text = "api_key: sk-1234567890abcdef"
        sanitized = DataSanitizer.sanitize_string(text)
        assert "sk-1234567890abcdef" not in sanitized
        
        text = "User email: user@example.com"
        sanitized = DataSanitizer.sanitize_string(text)
        assert "user@example.com" not in sanitized
        assert len(sanitized.split()[-1]) == 8
    
    def test_sanitize_dict_sensitive_keys(self):
        """Test dictionary sanitization with sensitive keys"""
        data = {
            "username": "testuser",
            "password": "secret123",
            "email": "user@test.com",
            "api_key": "sk-abcdef123456",
            "normal_field": "normal_value"
        }
        
        sanitized = DataSanitizer.sanitize_dict(data)
        
        assert sanitized["username"] == "testuser"
        assert sanitized["normal_field"] == "normal_value"
        
        assert sanitized["password"] != "secret123"
        assert sanitized["email"] != "user@test.com"
        assert sanitized["api_key"] != "sk-abcdef123456"
        
        assert "se*****23" in sanitized["password"]
    
    def test_sanitize_nested_dict(self):
        """Test nested dictionary sanitization"""
        data = {
            "user": {
                "credentials": {
                    "password": "nested_secret",
                    "token": "auth_token_123"
                },
                "profile": {
                    "name": "John Doe"
                }
            }
        }
        
        sanitized = DataSanitizer.sanitize_dict(data)
        
        assert sanitized["user"]["profile"]["name"] == "John Doe"
        
        credentials = sanitized["user"]["credentials"]
        assert credentials["password"] != "nested_secret"
        assert credentials["token"] != "auth_token_123"
    
    def test_sanitize_max_depth(self):
        """Test max depth protection"""
        data = {"level1": {"level2": {"level3": {"level4": {"level5": {"level6": "deep"}}}}}}
        
        sanitized = DataSanitizer.sanitize_dict(data, max_depth=3)
        
        assert "_truncated" in str(sanitized)
    
    def test_sanitize_list_values(self):
        """Test list sanitization"""
        data = {
            "passwords": ["secret1", "secret2", "secret3"],
            "users": ["user1", "user2"]
        }
        
        sanitized = DataSanitizer.sanitize_dict(data)
        
        assert all("secret" not in str(item) for item in sanitized["passwords"])
        assert sanitized["users"] == ["user1", "user2"]


class TestLogRateLimiter:
    """Test log rate limiting functionality"""
    
    def test_rate_limiter_allows_under_limit(self):
        """Test that requests under limit are allowed"""
        limiter = LogRateLimiter(max_logs_per_minute=5, max_logs_per_hour=10)
        
        for _ in range(5):
            assert limiter.is_allowed() == True
    
    def test_rate_limiter_blocks_over_minute_limit(self):
        """Test that requests over minute limit are blocked"""
        limiter = LogRateLimiter(max_logs_per_minute=3, max_logs_per_hour=10)
        
        for _ in range(3):
            assert limiter.is_allowed() == True
        
        assert limiter.is_allowed() == False
    
    def test_rate_limiter_blocks_over_hour_limit(self):
        """Test that requests over hour limit are blocked"""
        limiter = LogRateLimiter(max_logs_per_minute=100, max_logs_per_hour=2)
        
        for _ in range(2):
            assert limiter.is_allowed() == True
        
        assert limiter.is_allowed() == False
    
    @patch('aiows.middleware.logging.datetime')
    def test_rate_limiter_cleanup(self, mock_datetime):
        """Test that old log entries are cleaned up"""
        start_time = datetime(2023, 1, 1, 12, 0, 0)
        mock_datetime.now.return_value = start_time
        
        limiter = LogRateLimiter(max_logs_per_minute=5, max_logs_per_hour=10)
        
        for _ in range(5):
            assert limiter.is_allowed() == True
        
        assert limiter.is_allowed() == False
        
        mock_datetime.now.return_value = start_time + timedelta(minutes=2)
        
        assert limiter.is_allowed() == True


class TestSecureJSONFormatter:
    """Test JSON formatter functionality"""
    
    def test_json_formatter_basic(self):
        """Test basic JSON formatting"""
        formatter = SecureJSONFormatter()
        
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Test message", args=(), exc_info=None
        )
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert data["message"] == "Test message"
        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert "timestamp" in data
    
    def test_json_formatter_with_correlation_id(self):
        """Test JSON formatting with correlation ID"""
        formatter = SecureJSONFormatter()
        
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Test message", args=(), exc_info=None
        )
        record.correlation_id = "test-correlation-123"
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert data["correlation_id"] == "test-correlation-123"
    
    def test_json_formatter_with_structured_data(self):
        """Test JSON formatting with structured data"""
        formatter = SecureJSONFormatter()
        
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="Test message", args=(), exc_info=None
        )
        record.structured_data = {
            "event_type": "connection",
            "client_id": "client123",
            "processing_time_ms": 45.2
        }
        
        result = formatter.format(record)
        data = json.loads(result)
        
        assert data["event_type"] == "connection"
        assert data["client_id"] == "client123"
        assert data["processing_time_ms"] == 45.2


class TestLoggingMiddleware:
    """Test secure logging middleware functionality"""
    
    @pytest.fixture
    def mock_websocket(self):
        """Create a mock WebSocket for testing"""
        websocket = MagicMock(spec=WebSocket)
        websocket.context = {"user_id": "user123", "authenticated": True}
        websocket._websocket = MagicMock()
        websocket._websocket.remote_address = ("192.168.1.100", 8080)
        return websocket
    
    @pytest.fixture
    def logging_middleware(self):
        """Create logging middleware for testing"""
        return LoggingMiddleware(
            logger_name="test_logger",
            use_json_format=False,
            sanitize_data=True,
            enable_rate_limiting=False
        )
    
    def test_correlation_id_generation(self, logging_middleware, mock_websocket):
        """Test correlation ID generation and persistence"""
        corr_id_1 = logging_middleware._get_correlation_id(mock_websocket)
        assert corr_id_1 is not None
        assert len(corr_id_1) > 0
        
        corr_id_2 = logging_middleware._get_correlation_id(mock_websocket)
        assert corr_id_1 == corr_id_2
        
        logging_middleware._cleanup_correlation_id(mock_websocket)
        
        corr_id_3 = logging_middleware._get_correlation_id(mock_websocket)
        assert corr_id_3 != corr_id_1
    
    def test_client_info_sanitization(self, logging_middleware, mock_websocket):
        """Test that client info is properly sanitized"""
        client_info = logging_middleware._get_client_info(mock_websocket)
        
        assert "client_ip_hash" in client_info
        assert "192.168.1.100" not in str(client_info)
        
        assert "user_id_hash" in client_info
        assert "user123" not in str(client_info)
        
        assert client_info["authenticated"] is True
        
        assert "connection_id" in client_info
    
    def test_message_info_sanitization(self, logging_middleware):
        """Test that message info is properly sanitized"""
        message_data = {
            "type": "auth",
            "password": "secret123",
            "username": "testuser",
            "token": "bearer_token_abc"
        }
        
        message_info = logging_middleware._get_message_info(message_data)
        
        assert message_info["message_type"] == "auth"
        assert "message_size_bytes" in message_info
        assert "message_fingerprint" in message_info
        
        assert "message_content" not in message_info
    
    def test_message_content_when_enabled(self):
        """Test message content inclusion when explicitly enabled"""
        middleware = LoggingMiddleware(
            use_json_format=False,
            include_message_content=True,
            sanitize_data=True
        )
        
        message_data = {
            "type": "auth",
            "password": "secret123",
            "username": "testuser"
        }
        
        message_info = middleware._get_message_info(message_data)
        
        assert "message_content" in message_info
        content = message_info["message_content"]
        assert content["username"] == "testuser"
        assert "secret123" not in str(content)
    
    @pytest.mark.asyncio
    async def test_on_connect_logging(self, logging_middleware, mock_websocket):
        """Test connection event logging"""
        handler = AsyncMock(return_value="connection_result")
        
        with patch.object(logging_middleware, '_log_structured') as mock_log:
            result = await logging_middleware.on_connect(handler, mock_websocket)
            
            assert result == "connection_result"
            assert mock_log.call_count == 2
            
            first_call = mock_log.call_args_list[0]
            assert first_call[0][0] == logging.INFO
            assert "established" in first_call[0][1]
            assert first_call[1]["event_type"] == "connection_established"
    
    @pytest.mark.asyncio
    async def test_on_connect_error_logging(self, logging_middleware, mock_websocket):
        """Test connection error logging"""
        handler = AsyncMock(side_effect=ValueError("Connection failed"))
        
        with patch.object(logging_middleware, '_log_structured') as mock_log:
            with pytest.raises(ValueError):
                await logging_middleware.on_connect(handler, mock_websocket)
            
            assert mock_log.call_count == 2
            
            error_call = mock_log.call_args_list[-1]
            assert error_call[0][0] == logging.ERROR
            assert error_call[1]["event_type"] == "connection_error"
            assert error_call[1]["error_type"] == "ValueError"
            assert "Connection failed" in error_call[1]["error_message"]
    
    @pytest.mark.asyncio
    async def test_on_message_logging(self, logging_middleware, mock_websocket):
        """Test message event logging"""
        message_data = {"type": "chat", "content": "Hello world"}
        handler = AsyncMock(return_value="message_result")
        
        with patch.object(logging_middleware, '_log_structured') as mock_log:
            result = await logging_middleware.on_message(
                handler, mock_websocket, message_data
            )
            
            assert result == "message_result"
            assert mock_log.call_count == 2
            
            received_call = mock_log.call_args_list[0]
            assert received_call[1]["event_type"] == "message_received"
            assert received_call[1]["message_type"] == "chat"
    
    @pytest.mark.asyncio
    async def test_on_message_performance_warning(self, logging_middleware, mock_websocket):
        """Test performance warning for slow message processing"""
        message_data = {"type": "slow"}
        
        async def slow_handler(*args, **kwargs):
            await asyncio.sleep(0.2)
            return "slow_result"
        
        with patch.object(logging_middleware, '_log_structured') as mock_log:
            await logging_middleware.on_message(slow_handler, mock_websocket, message_data)
            
            processed_call = mock_log.call_args_list[-1]
            assert processed_call[0][0] == logging.WARNING
            assert processed_call[1]["performance_warning"] is True
            assert processed_call[1]["processing_time_ms"] > 100
    
    @pytest.mark.asyncio
    async def test_on_disconnect_logging(self, logging_middleware, mock_websocket):
        """Test disconnect event logging"""
        reason = "Client closed connection"
        handler = AsyncMock(return_value="disconnect_result")
        
        with patch.object(logging_middleware, '_log_structured') as mock_log:
            result = await logging_middleware.on_disconnect(
                handler, mock_websocket, reason
            )
            
            assert result == "disconnect_result"
            mock_log.assert_called_once()
            
            call_args = mock_log.call_args
            assert call_args[1]["event_type"] == "connection_closed"
            assert "Client closed connection" in call_args[1]["disconnect_reason"]
    
    @pytest.mark.asyncio
    async def test_correlation_id_cleanup_on_disconnect(self, logging_middleware, mock_websocket):
        """Test that correlation ID is cleaned up on disconnect"""
        corr_id = logging_middleware._get_correlation_id(mock_websocket)
        assert corr_id in logging_middleware.connection_correlations.values()
        
        handler = AsyncMock()
        await logging_middleware.on_disconnect(handler, mock_websocket, "test")
        
        assert corr_id not in logging_middleware.connection_correlations.values()
    
    def test_rate_limiting_integration(self):
        """Test rate limiting integration"""
        middleware = LoggingMiddleware(
            enable_rate_limiting=True,
            max_logs_per_minute=2,
            max_logs_per_hour=5
        )
        
        assert middleware._should_log() is True
        assert middleware._should_log() is True
        
        assert middleware._should_log() is False
    
    def test_backwards_compatibility(self):
        """Test that basic LoggingMiddleware API is preserved"""
        middleware = LoggingMiddleware()
        assert middleware is not None
        
        middleware = LoggingMiddleware(logger_name="custom_logger")
        assert middleware.logger.name == "custom_logger"
    
    def test_sensitive_data_not_in_logs(self, logging_middleware, mock_websocket):
        """Integration test: ensure sensitive data never appears in logs"""
        sensitive_message = {
            "type": "login",
            "username": "testuser",
            "password": "super_secret_password",
            "api_key": "sk-1234567890abcdef",
            "email": "user@company.com"
        }
        
        with patch.object(logging_middleware.logger, 'log') as mock_log:
            message_info = logging_middleware._get_message_info(sensitive_message)
            
            info_str = str(message_info)
            assert "super_secret_password" not in info_str
            assert "sk-1234567890abcdef" not in info_str
            assert "user@company.com" not in info_str
    
    def test_json_logging_format(self):
        """Test JSON logging format"""
        middleware = LoggingMiddleware(
            use_json_format=True,
            enable_rate_limiting=False
        )
        
        assert len(middleware.logger.handlers) > 0
        handler = middleware.logger.handlers[0]
        assert isinstance(handler.formatter, SecureJSONFormatter)


class TestSecurityCompliance:
    """Test security compliance requirements"""
    
    def test_no_plain_text_passwords_in_any_output(self):
        """Comprehensive test that passwords never appear in plain text"""
        middleware = LoggingMiddleware(include_message_content=True, sanitize_data=True)
        
        test_cases = [
            {"password": "plaintext123"},
            {"passwd": "secret456"},
            {"pass": "hidden789"},
            {"user_password": "test_pass"},
            {"PASSWORD": "UPPERCASE"},
        ]
        
        for test_case in test_cases:
            message_info = middleware._get_message_info(test_case)
            output = json.dumps(message_info)
            
            for key, value in test_case.items():
                assert value not in output, f"Password '{value}' found in output: {output}"
    
    def test_pii_data_protection(self):
        """Test that PII data is protected"""
        test_data = {
            "email": "john.doe@company.com",
            "phone": "+1-555-123-4567",
            "ssn": "123-45-6789",
            "credit_card": "4532-1234-5678-9012"
        }
        
        sanitized = DataSanitizer.sanitize_dict(test_data)
        output = json.dumps(sanitized)
        
        assert "john.doe@company.com" not in output
        assert "+1-555-123-4567" not in output
        assert "123-45-6789" not in output
        assert "4532-1234-5678-9012" not in output
    
    def test_correlation_id_format_security(self):
        """Test that correlation IDs are properly formatted and unique"""
        middleware = LoggingMiddleware()
        
        ids = [middleware._generate_correlation_id() for _ in range(100)]
        
        assert len(set(ids)) == len(ids)
        
        for corr_id in ids:
            uuid.UUID(corr_id)
            assert len(corr_id) == 36


if __name__ == "__main__":
    pytest.main([__file__]) 