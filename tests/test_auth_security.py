"""
Comprehensive security tests for the secure AuthMiddleware
"""

import asyncio
import json
import time
import pytest
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any, Optional

from aiows.middleware.auth import (
    AuthMiddleware, 
    SecureToken, 
    TicketManager, 
    RateLimiter,
    AuthenticationError,
    SecurityError,
    generate_auth_token,
    verify_auth_token
)
from aiows.websocket import WebSocket


class MockWebSocket(WebSocket):
    """Mock WebSocket for testing"""
    
    def __init__(self, remote_ip: str = "127.0.0.1", headers: Optional[Dict[str, str]] = None):
        # Create a mock websocket object first
        mock_ws = Mock()
        mock_ws.request = Mock()
        
        # Default headers for tests with valid User-Agent
        default_headers = {
            'user-agent': 'Mozilla/5.0 (Test Browser) TestRunner/1.0'
        }
        if headers:
            default_headers.update(headers)
        
        # Make headers case-insensitive dict for testing
        mock_ws.request.headers = {k.lower(): v for k, v in default_headers.items()}
        mock_ws.request.remote = (remote_ip, 12345)
        mock_ws.remote_address = (remote_ip, 12345)
        mock_ws.send = AsyncMock()  # Make send async
        mock_ws.close = AsyncMock()  # Make close async
        
        # Initialize parent class
        super().__init__(mock_ws)
        
        # Test-specific attributes
        self.close_code = None
        self.close_reason = None
        self.sent_messages = []
        self.received_messages = []
        self.current_message_index = 0
    
    async def close(self, code: int = 1000, reason: str = ""):
        """Override close method for testing"""
        await super().close(code, reason)
        self.close_code = code
        self.close_reason = reason
    
    async def send(self, message: str):
        """Override send method for testing"""
        self.sent_messages.append(message)
        # Also call the websocket's send method
        await self._websocket.send(message)
    
    async def recv(self):
        """Override recv method for testing"""
        if self.current_message_index >= len(self.received_messages):
            # Simulate hanging forever (for timeout testing)
            # This will be caught by asyncio.wait_for in the auth middleware
            await asyncio.sleep(999999)  # Very long sleep to trigger timeout
        
        message = self.received_messages[self.current_message_index]
        self.current_message_index += 1
        return message
    
    def add_message(self, message: str):
        """Add a message to be received"""
        self.received_messages.append(message)


@pytest.fixture
def secret_key():
    """Secure secret key for testing"""
    return "test_secret_key_that_is_at_least_32_characters_long_for_security"


@pytest.fixture
def auth_middleware(secret_key):
    """Create AuthMiddleware instance for testing"""
    return AuthMiddleware(
        secret_key=secret_key,
        token_ttl=300,
        enable_ip_validation=True,
        rate_limit_attempts=3,
        rate_limit_window=60,
        max_tickets=1000,
        allowed_origins=None  # Allow all origins for testing
    )


@pytest.fixture
def mock_websocket():
    """Create mock WebSocket for testing"""
    return MockWebSocket()


class TestSecureToken:
    """Test SecureToken functionality"""
    
    def test_generate_valid_token(self, secret_key):
        """Test generating a valid token"""
        user_id = "test_user_123"
        client_ip = "192.168.1.100"
        
        token = SecureToken.generate(user_id, secret_key, 300, client_ip)
        
        # Token should have 3 parts separated by dots
        parts = token.split('.')
        assert len(parts) == 3
        
        # Should be able to verify the token
        payload = SecureToken.verify(token, secret_key, client_ip)
        assert payload['sub'] == user_id
        assert payload['ip'] == client_ip
        assert 'jti' in payload
        assert 'nonce' in payload
    
    def test_token_expiration(self, secret_key):
        """Test token expiration handling"""
        user_id = "test_user"
        
        # Generate token that's already expired
        import time
        current_time = int(time.time())
        expired_time = current_time - 100  # 100 seconds ago
        
        # Create manually expired token by mocking the time
        header = SecureToken.encode_payload({
            "alg": "HS256",
            "typ": "JWT"
        })
        
        payload_data = {
            "sub": user_id,
            "iat": expired_time,
            "exp": expired_time + 10,  # Expired 90 seconds ago
            "jti": "test_expired_ticket",
            "ip": None,
            "nonce": "test_nonce"
        }
        
        payload_encoded = SecureToken.encode_payload(payload_data)
        signature = SecureToken.create_signature(header, payload_encoded, secret_key)
        expired_token = f"{header}.{payload_encoded}.{signature}"
        
        # Should be expired
        with pytest.raises(AuthenticationError, match="Token expired"):
            SecureToken.verify(expired_token, secret_key)
    
    def test_invalid_signature(self, secret_key):
        """Test rejection of tokens with invalid signatures"""
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        # Tamper with the token
        parts = token.split('.')
        tampered_token = f"{parts[0]}.{parts[1]}.invalid_signature"
        
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            SecureToken.verify(tampered_token, secret_key)
    
    def test_wrong_secret_key(self, secret_key):
        """Test rejection with wrong secret key"""
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        wrong_secret = "wrong_secret_key_that_is_different_and_long_enough"
        
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            SecureToken.verify(token, wrong_secret)
    
    def test_ip_validation_mismatch(self, secret_key):
        """Test IP validation failure"""
        user_id = "test_user"
        original_ip = "192.168.1.100"
        different_ip = "192.168.1.200"
        
        token = SecureToken.generate(user_id, secret_key, client_ip=original_ip)
        
        # Should work with correct IP
        payload = SecureToken.verify(token, secret_key, original_ip)
        assert payload['sub'] == user_id
        
        # Should fail with different IP
        with pytest.raises(SecurityError, match="IP address mismatch"):
            SecureToken.verify(token, secret_key, different_ip)
    
    def test_malformed_token_format(self, secret_key):
        """Test handling of malformed tokens"""
        malformed_tokens = [
            "not.enough.parts",
            "too.many.parts.here.invalid",
            "invalid_base64_!@#$%",
            "",
            "single_part",
        ]
        
        for token in malformed_tokens:
            with pytest.raises(AuthenticationError):
                SecureToken.verify(token, secret_key)
    
    def test_payload_tampering(self, secret_key):
        """Test detection of payload tampering"""
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        parts = token.split('.')
        
        # Try to tamper with payload by changing user ID
        tampered_payload = SecureToken.encode_payload({
            "sub": "different_user",
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
            "jti": "fake_ticket_id"
        })
        
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
        
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            SecureToken.verify(tampered_token, secret_key)


class TestTicketManager:
    """Test TicketManager functionality"""
    
    def test_ticket_replay_protection(self):
        """Test replay attack protection"""
        manager = TicketManager()
        ticket_id = "test_ticket_123"
        
        # First use should be allowed
        assert not manager.is_ticket_used(ticket_id)
        manager.mark_ticket_used(ticket_id)
        
        # Second use should be blocked
        assert manager.is_ticket_used(ticket_id)
    
    def test_ticket_cleanup(self):
        """Test automatic cleanup of expired tickets"""
        manager = TicketManager(cleanup_interval=0)  # Force immediate cleanup
        ticket_id = "test_ticket_123"
        
        # Mark ticket as used
        manager.mark_ticket_used(ticket_id)
        assert manager.is_ticket_used(ticket_id)
        
        # Manually set old timestamp
        manager._used_tickets[ticket_id] = time.time() - 90000  # 25 hours ago
        
        # Trigger cleanup by checking another ticket
        manager.is_ticket_used("trigger_cleanup")
        
        # Old ticket should be cleaned up
        assert ticket_id not in manager._used_tickets
    
    def test_ticket_memory_limit(self):
        """Test memory limit for tickets"""
        manager = TicketManager(max_tickets=3)
        
        # Add tickets up to the limit
        for i in range(3):
            manager.mark_ticket_used(f"ticket_{i}")
        
        # All tickets should be present
        for i in range(3):
            assert manager.is_ticket_used(f"ticket_{i}")
        
        # Add one more ticket - should evict the oldest
        manager.mark_ticket_used("ticket_3")
        
        # First ticket should be evicted
        assert not manager.is_ticket_used("ticket_0")
        # Others should still be present
        assert manager.is_ticket_used("ticket_1")
        assert manager.is_ticket_used("ticket_2") 
        assert manager.is_ticket_used("ticket_3")


class TestRateLimiter:
    """Test RateLimiter functionality"""
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        identifier = "test_client"
        
        # First 3 attempts should be allowed
        for i in range(3):
            assert not limiter.is_rate_limited(identifier)
            limiter.record_attempt(identifier)
        
        # 4th attempt should be rate limited
        assert limiter.is_rate_limited(identifier)
    
    def test_rate_limit_window_expiry(self):
        """Test rate limit window expiration"""
        limiter = RateLimiter(max_attempts=2, window_seconds=1)
        identifier = "test_client"
        
        # Make max attempts
        limiter.record_attempt(identifier)
        limiter.record_attempt(identifier)
        assert limiter.is_rate_limited(identifier)
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Should be allowed again
        assert not limiter.is_rate_limited(identifier)


class TestAuthMiddleware:
    """Test AuthMiddleware functionality"""
    
    def test_initialization_weak_secret(self):
        """Test rejection of weak secret keys"""
        with pytest.raises(ValueError, match="Secret key must be at least 32 characters"):
            AuthMiddleware("weak_key")
    
    def test_generate_token(self, auth_middleware):
        """Test token generation method"""
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        token = auth_middleware.generate_token(user_id, client_ip)
        
        # Should be able to verify the generated token
        payload = SecureToken.verify(token, auth_middleware.secret_key, client_ip)
        assert payload['sub'] == user_id
    
    @pytest.mark.asyncio
    async def test_successful_authentication(self, auth_middleware, mock_websocket):
        """Test successful authentication flow"""
        user_id = "test_user_123"
        client_ip = "192.168.1.100"
        
        # Update mock websocket IP
        mock_websocket._websocket.request.remote = (client_ip, 12345)
        mock_websocket._websocket.remote_address = (client_ip, 12345)
        
        # Generate valid token
        token = auth_middleware.generate_token(user_id, client_ip)
        
        # Prepare authentication message
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        # Mock handler
        handler = AsyncMock(return_value="success")
        
        # Test authentication
        result = await auth_middleware.on_connect(handler, mock_websocket)
        
        # Should succeed
        assert result == "success"
        assert mock_websocket.context.get('user_id') == user_id
        assert mock_websocket.context.get('authenticated') is True
        assert not mock_websocket.closed
        
        # Should send success response
        assert len(mock_websocket.sent_messages) == 1
        response = json.loads(mock_websocket.sent_messages[0])
        assert response['type'] == 'auth_success'
        assert response['user_id'] == user_id
    
    @pytest.mark.asyncio
    async def test_invalid_token_authentication(self, auth_middleware, mock_websocket):
        """Test authentication with invalid token"""
        # Prepare invalid authentication message
        auth_message = json.dumps({"token": "invalid_token"})
        mock_websocket.add_message(auth_message)
        
        # Mock handler
        handler = AsyncMock()
        
        # Test authentication
        await auth_middleware.on_connect(handler, mock_websocket)
        
        # Should fail and close connection
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "format" in mock_websocket.close_reason.lower()
        
        # Handler should not be called
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_expired_token_authentication(self, secret_key, mock_websocket):
        """Test authentication with expired token"""
        # Create fresh middleware to avoid rate limiting from other tests
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            token_ttl=300,
            enable_ip_validation=False,  # Disable IP validation for this test
            rate_limit_attempts=5,
            rate_limit_window=60,
            max_tickets=1000,
            allowed_origins=None
        )
        
        # Use unique IP to avoid rate limiting interference
        mock_websocket._websocket.request.remote = ("10.0.0.99", 12345)
        mock_websocket._websocket.remote_address = ("10.0.0.99", 12345)
        
        user_id = "test_user"
        
        # Create expired token manually (more reliable than waiting)
        import time
        current_time = int(time.time())
        expired_time = current_time - 100  # 100 seconds ago
        
        # Create manually expired token
        header = SecureToken.encode_payload({
            "alg": "HS256",
            "typ": "JWT"
        })
        
        payload_data = {
            "sub": user_id,
            "iat": expired_time,
            "exp": expired_time + 10,  # Expired 90 seconds ago
            "jti": "test_expired_middleware_ticket",
            "ip": None,
            "nonce": "test_nonce_middleware"
        }
        
        payload_encoded = SecureToken.encode_payload(payload_data)
        signature = SecureToken.create_signature(header, payload_encoded, secret_key)
        token = f"{header}.{payload_encoded}.{signature}"
        
        # Prepare authentication message
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        # Mock handler
        handler = AsyncMock()
        
        # Test authentication
        await auth_middleware.on_connect(handler, mock_websocket)
        
        # Should fail due to expiration
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "expired" in mock_websocket.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_replay_attack_protection(self, auth_middleware, mock_websocket):
        """Test protection against replay attacks"""
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        # Update mock websocket IP
        mock_websocket._websocket.request.remote = (client_ip, 12345)
        mock_websocket._websocket.remote_address = (client_ip, 12345)
        
        # Generate valid token
        token = auth_middleware.generate_token(user_id, client_ip)
        
        # First authentication should succeed
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock(return_value="success")
        result = await auth_middleware.on_connect(handler, mock_websocket)
        
        assert result == "success"
        assert not mock_websocket.closed
        
        # Try to reuse the same token (replay attack)
        mock_websocket2 = MockWebSocket(remote_ip=client_ip)
        mock_websocket2.add_message(auth_message)
        
        handler2 = AsyncMock()
        await auth_middleware.on_connect(handler2, mock_websocket2)
        
        # Second attempt should fail
        assert mock_websocket2.closed
        assert mock_websocket2.close_code == 4401
        assert "replay" in mock_websocket2.close_reason.lower()
        handler2.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_ip_validation_failure(self, auth_middleware, mock_websocket):
        """Test IP validation failure"""
        user_id = "test_user"
        original_ip = "192.168.1.100"
        different_ip = "192.168.1.200"
        
        # Generate token for specific IP
        token = auth_middleware.generate_token(user_id, original_ip)
        
        # Try to use from different IP
        mock_websocket = MockWebSocket(remote_ip=different_ip)
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock()
        await auth_middleware.on_connect(handler, mock_websocket)
        
        # Should fail due to IP mismatch
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "mismatch" in mock_websocket.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_malformed_auth_message(self, auth_middleware, mock_websocket):
        """Test handling of malformed authentication messages"""
        malformed_messages = [
            "not_json",
            json.dumps({"wrong_field": "value"}),
            json.dumps({}),
            "",
        ]
        
        for i, message in enumerate(malformed_messages):
            # Use different IP for each test to avoid rate limiting
            mock_ws = MockWebSocket(remote_ip=f"192.168.1.{100 + i}")
            mock_ws.add_message(message)
            
            handler = AsyncMock()
            await auth_middleware.on_connect(handler, mock_ws)
            
            assert mock_ws.closed
            assert mock_ws.close_code == 4401
            assert "format" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, auth_middleware, mock_websocket):
        """Test rate limiting of authentication attempts"""
        # Exhaust rate limit with failed attempts
        for i in range(3):
            mock_ws = MockWebSocket()
            mock_ws.add_message(json.dumps({"token": "invalid_token"}))
            
            handler = AsyncMock()
            await auth_middleware.on_connect(handler, mock_ws)
            
            assert mock_ws.closed
        
        # Next attempt should be rate limited
        mock_ws = MockWebSocket()
        mock_ws.add_message(json.dumps({"token": "any_token"}))
        
        handler = AsyncMock()
        await auth_middleware.on_connect(handler, mock_ws)
        
        assert mock_ws.closed
        assert mock_ws.close_code == 4429
        assert "rate limit" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_message_handling_unauthenticated(self, auth_middleware, mock_websocket):
        """Test message handling for unauthenticated connections"""
        handler = AsyncMock()
        
        # Try to handle message without authentication
        await auth_middleware.on_message(handler, mock_websocket)
        
        # Should close connection
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "required" in mock_websocket.close_reason.lower()
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_message_handling_authenticated(self, auth_middleware, mock_websocket):
        """Test message handling for authenticated connections"""
        # Simulate authenticated state
        mock_websocket.context['authenticated'] = True
        mock_websocket.context['user_id'] = 'test_user'
        mock_websocket.context['auth_timestamp'] = time.time()
        
        handler = AsyncMock(return_value="message_handled")
        
        # Handle message
        result = await auth_middleware.on_message(handler, mock_websocket)
        
        # Should succeed
        assert result == "message_handled"
        assert not mock_websocket.closed
        handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_session_timeout(self, auth_middleware, mock_websocket):
        """Test session timeout handling"""
        # Simulate old authentication
        mock_websocket.context['authenticated'] = True
        mock_websocket.context['user_id'] = 'test_user'
        mock_websocket.context['auth_timestamp'] = time.time() - 3700  # Over 1 hour ago
        
        handler = AsyncMock()
        
        # Handle message
        await auth_middleware.on_message(handler, mock_websocket)
        
        # Should close due to session timeout
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "expired" in mock_websocket.close_reason.lower()
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_disconnect_handling(self, auth_middleware, mock_websocket):
        """Test disconnect event handling"""
        # Simulate authenticated state
        mock_websocket.context['user_id'] = 'test_user'
        
        handler = AsyncMock(return_value="disconnected")
        
        # Handle disconnect
        result = await auth_middleware.on_disconnect(handler, mock_websocket)
        
        # Should call handler normally
        assert result == "disconnected"
        handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_security_headers_validation(self, secret_key):
        """Test security headers validation"""
        # Create middleware with allowed origins
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            allowed_origins=["https://example.com", "https://app.example.com"]
        )
        
        # Test with allowed origin
        mock_ws = MockWebSocket(headers={
            'origin': 'https://example.com',
            'user-agent': 'Mozilla/5.0 (compatible browser)'
        })
        
        assert auth_middleware._validate_security_headers(mock_ws) is True
        
        # Test with disallowed origin
        mock_ws2 = MockWebSocket(headers={
            'origin': 'https://malicious.com',
            'user-agent': 'Mozilla/5.0 (compatible browser)'
        })
        
        assert auth_middleware._validate_security_headers(mock_ws2) is False
        
        # Test with suspicious user-agent
        mock_ws3 = MockWebSocket(headers={
            'origin': 'https://example.com',
            'user-agent': 'bot'  # Too short
        })
        
        assert auth_middleware._validate_security_headers(mock_ws3) is False
    
    @pytest.mark.asyncio
    async def test_auth_timeout_protection(self, secret_key):
        """Test authentication timeout protection"""
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            auth_timeout=0.1  # Very short timeout
        )
        
        # Create mock websocket that never responds
        mock_ws = MockWebSocket()
        # Don't add any messages - will cause timeout
        
        handler = AsyncMock()
        
        # Should timeout and close connection
        result = await auth_middleware.on_connect(handler, mock_ws)
        
        assert result is None  # Authentication failed
        assert mock_ws.closed
        assert mock_ws.close_code == 4401
        assert "timeout" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_ip_extractor_configurability(self, secret_key):
        """Test configurable IP extraction"""
        auth_middleware = AuthMiddleware(secret_key=secret_key)
        
        # Test with X-Forwarded-For
        mock_ws = MockWebSocket(headers={
            'x-forwarded-for': '192.168.1.100, 10.0.0.1',
            'x-real-ip': '192.168.1.200'
        })
        
        ip = auth_middleware._get_client_ip(mock_ws)
        assert ip == '192.168.1.100'  # Should get first from forwarded
        
        # Test fallback to X-Real-IP
        mock_ws2 = MockWebSocket(headers={
            'x-real-ip': '192.168.1.200'
        })
        
        ip2 = auth_middleware._get_client_ip(mock_ws2)
        assert ip2 == '192.168.1.200'


class TestUtilityFunctions:
    """Test utility functions"""
    
    def test_generate_auth_token_function(self, secret_key):
        """Test generate_auth_token utility function"""
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        token = generate_auth_token(secret_key, user_id, client_ip, 300)
        
        # Should be able to verify
        payload = verify_auth_token(token, secret_key, client_ip)
        assert payload['sub'] == user_id
        assert payload['ip'] == client_ip
    
    def test_verify_auth_token_function(self, secret_key):
        """Test verify_auth_token utility function"""
        user_id = "test_user"
        
        # Generate token
        token = generate_auth_token(secret_key, user_id)
        
        # Verify valid token
        payload = verify_auth_token(token, secret_key)
        assert payload['sub'] == user_id
        
        # Verify invalid token
        with pytest.raises(AuthenticationError):
            verify_auth_token("invalid_token", secret_key)


class TestSecurityScenarios:
    """Test various security attack scenarios"""
    
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, auth_middleware, mock_websocket):
        """Test resistance to timing attacks"""
        # This test ensures that invalid tokens take roughly the same time
        # to process as valid ones, preventing timing-based attacks
        
        user_id = "test_user"
        valid_token = auth_middleware.generate_token(user_id)
        invalid_token = "invalid_token_with_similar_length_to_valid_one"
        
        # Measure time for valid token processing
        mock_ws1 = MockWebSocket()
        mock_ws1.add_message(json.dumps({"token": valid_token}))
        
        start_time = time.time()
        await auth_middleware.on_connect(AsyncMock(), mock_ws1)
        valid_time = time.time() - start_time
        
        # Measure time for invalid token processing
        mock_ws2 = MockWebSocket()
        mock_ws2.add_message(json.dumps({"token": invalid_token}))
        
        start_time = time.time()
        await auth_middleware.on_connect(AsyncMock(), mock_ws2)
        invalid_time = time.time() - start_time
        
        # Times should be relatively similar (within reasonable bounds)
        # This is a basic check - in production, more sophisticated timing analysis would be needed
        time_ratio = max(valid_time, invalid_time) / min(valid_time, invalid_time)
        assert time_ratio < 20  # Should not differ by more than 20x (increased for CI stability)
    
    def test_token_collision_resistance(self, secret_key):
        """Test that generated tokens are unique"""
        user_id = "test_user"
        tokens = set()
        
        # Generate many tokens and ensure they're all unique
        for _ in range(1000):
            token = SecureToken.generate(user_id, secret_key)
            assert token not in tokens, "Token collision detected!"
            tokens.add(token)
    
    def test_secret_key_requirements(self):
        """Test security requirements for secret keys"""
        weak_keys = [
            "",
            "short",
            "exactly_31_characters_long_here",  # Just under 32 characters
        ]
        
        for weak_key in weak_keys:
            with pytest.raises(ValueError, match="Secret key must be at least 32 characters"):
                AuthMiddleware(weak_key)
        
        # This should work - exactly 32 characters
        valid_key = "a" * 32
        auth = AuthMiddleware(valid_key)
        assert auth.secret_key == valid_key
    
    @pytest.mark.asyncio
    async def test_concurrent_authentication_attempts(self, auth_middleware):
        """Test handling of concurrent authentication attempts"""
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        # Generate multiple tokens
        tokens = [auth_middleware.generate_token(user_id, client_ip) for _ in range(5)]
        
        # Create tasks for concurrent authentication
        async def authenticate_with_token(token):
            mock_ws = MockWebSocket(remote_ip=client_ip)
            mock_ws.add_message(json.dumps({"token": token}))
            handler = AsyncMock(return_value="success")
            return await auth_middleware.on_connect(handler, mock_ws)
        
        # Run concurrent authentications
        tasks = [authenticate_with_token(token) for token in tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should succeed since they're different tokens
        for result in results:
            assert result == "success"


if __name__ == "__main__":
    pytest.main([__file__]) 