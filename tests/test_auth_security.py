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
    def __init__(self, remote_ip: str = "127.0.0.1", headers: Optional[Dict[str, str]] = None):
        mock_ws = Mock()
        mock_ws.request = Mock()
        
        default_headers = {
            'user-agent': 'Mozilla/5.0 (Test Browser) TestRunner/1.0'
        }
        if headers:
            default_headers.update(headers)
        
        mock_ws.request.headers = {k.lower(): v for k, v in default_headers.items()}
        mock_ws.request.remote = (remote_ip, 12345)
        mock_ws.remote_address = (remote_ip, 12345)
        mock_ws.send = AsyncMock()
        mock_ws.close = AsyncMock()
        
        super().__init__(mock_ws)
        
        self.close_code = None
        self.close_reason = None
        self.sent_messages = []
        self.received_messages = []
        self.current_message_index = 0
    
    async def close(self, code: int = 1000, reason: str = ""):
        await super().close(code, reason)
        self.close_code = code
        self.close_reason = reason
    
    async def send(self, message: str):
        self.sent_messages.append(message)
        await self._websocket.send(message)
    
    async def recv(self):
        if self.current_message_index >= len(self.received_messages):
            await asyncio.sleep(999999)
        
        message = self.received_messages[self.current_message_index]
        self.current_message_index += 1
        return message
    
    def add_message(self, message: str):
        self.received_messages.append(message)


@pytest.fixture
def secret_key():
    return "test_secret_key_that_is_at_least_32_characters_long_for_security"


@pytest.fixture
def auth_middleware(secret_key):
    return AuthMiddleware(
        secret_key=secret_key,
        token_ttl=300,
        enable_ip_validation=True,
        rate_limit_attempts=3,
        rate_limit_window=60,
        max_tickets=1000,
        allowed_origins=None
    )


@pytest.fixture
def mock_websocket():
    return MockWebSocket()


class TestSecureToken:
    def test_generate_valid_token(self, secret_key):
        user_id = "test_user_123"
        client_ip = "192.168.1.100"
        
        token = SecureToken.generate(user_id, secret_key, 300, client_ip)
        
        parts = token.split('.')
        assert len(parts) == 3
        
        payload = SecureToken.verify(token, secret_key, client_ip)
        assert payload['sub'] == user_id
        assert payload['ip'] == client_ip
        assert 'jti' in payload
        assert 'nonce' in payload
    
    def test_token_expiration(self, secret_key):
        user_id = "test_user"
        
        current_time = int(time.time())
        expired_time = current_time - 100
        
        header = SecureToken.encode_payload({
            "alg": "HS256",
            "typ": "JWT"
        })
        
        payload_data = {
            "sub": user_id,
            "iat": expired_time,
            "exp": expired_time + 10,
            "jti": "test_expired_ticket",
            "ip": None,
            "nonce": "test_nonce"
        }
        
        payload_encoded = SecureToken.encode_payload(payload_data)
        signature = SecureToken.create_signature(header, payload_encoded, secret_key)
        expired_token = f"{header}.{payload_encoded}.{signature}"
        
        with pytest.raises(AuthenticationError, match="Token expired"):
            SecureToken.verify(expired_token, secret_key)
    
    def test_invalid_signature(self, secret_key):
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        parts = token.split('.')
        tampered_token = f"{parts[0]}.{parts[1]}.invalid_signature"
        
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            SecureToken.verify(tampered_token, secret_key)
    
    def test_wrong_secret_key(self, secret_key):
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        wrong_secret = "wrong_secret_key_that_is_different_and_long_enough"
        
        with pytest.raises(AuthenticationError, match="Invalid token signature"):
            SecureToken.verify(token, wrong_secret)
    
    def test_ip_validation_mismatch(self, secret_key):
        user_id = "test_user"
        original_ip = "192.168.1.100"
        different_ip = "192.168.1.200"
        
        token = SecureToken.generate(user_id, secret_key, client_ip=original_ip)
        
        payload = SecureToken.verify(token, secret_key, original_ip)
        assert payload['sub'] == user_id
        
        with pytest.raises(SecurityError, match="IP address mismatch"):
            SecureToken.verify(token, secret_key, different_ip)
    
    def test_malformed_token_format(self, secret_key):
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
        user_id = "test_user"
        token = SecureToken.generate(user_id, secret_key)
        
        parts = token.split('.')
        
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
    def test_ticket_replay_protection(self):
        manager = TicketManager()
        ticket_id = "test_ticket_123"
        
        assert not manager.is_ticket_used(ticket_id)
        manager.mark_ticket_used(ticket_id)
        
        assert manager.is_ticket_used(ticket_id)
    
    def test_ticket_cleanup(self):
        manager = TicketManager(cleanup_interval=0)
        ticket_id = "test_ticket_123"
        
        manager.mark_ticket_used(ticket_id)
        assert manager.is_ticket_used(ticket_id)
        
        manager._used_tickets[ticket_id] = time.time() - 90000
        
        manager.is_ticket_used("trigger_cleanup")
        
        assert ticket_id not in manager._used_tickets
    
    def test_ticket_memory_limit(self):
        manager = TicketManager(max_tickets=3)
        
        for i in range(3):
            manager.mark_ticket_used(f"ticket_{i}")
        
        for i in range(3):
            assert manager.is_ticket_used(f"ticket_{i}")
        
        manager.mark_ticket_used("ticket_3")
        
        assert not manager.is_ticket_used("ticket_0")
        assert manager.is_ticket_used("ticket_1")
        assert manager.is_ticket_used("ticket_2") 
        assert manager.is_ticket_used("ticket_3")


class TestRateLimiter:
    def test_rate_limiting(self):
        limiter = RateLimiter(max_attempts=3, window_seconds=60)
        identifier = "test_client"
        
        for i in range(3):
            assert not limiter.is_rate_limited(identifier)
            limiter.record_attempt(identifier)
        
        assert limiter.is_rate_limited(identifier)
    
    def test_rate_limit_window_expiry(self):
        limiter = RateLimiter(max_attempts=2, window_seconds=1)
        identifier = "test_client"
        
        limiter.record_attempt(identifier)
        limiter.record_attempt(identifier)
        assert limiter.is_rate_limited(identifier)
        
        time.sleep(1.1)
        
        assert not limiter.is_rate_limited(identifier)


class TestAuthMiddleware:
    def test_initialization_weak_secret(self):
        with pytest.raises(ValueError, match="Secret key must be at least 32 characters"):
            AuthMiddleware("weak_key")
    
    def test_generate_token(self, auth_middleware):
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        token = auth_middleware.generate_token(user_id, client_ip)
        
        payload = SecureToken.verify(token, auth_middleware.secret_key, client_ip)
        assert payload['sub'] == user_id
    
    @pytest.mark.asyncio
    async def test_successful_authentication(self, auth_middleware, mock_websocket):
        user_id = "test_user_123"
        client_ip = "192.168.1.100"
        
        mock_websocket._websocket.request.remote = (client_ip, 12345)
        mock_websocket._websocket.remote_address = (client_ip, 12345)
        
        token = auth_middleware.generate_token(user_id, client_ip)
        
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock(return_value="success")
        
        result = await auth_middleware.on_connect(handler, mock_websocket)
        
        assert result == "success"
        assert mock_websocket.context.get('user_id') == user_id
        assert mock_websocket.context.get('authenticated') is True
        assert not mock_websocket.closed
        
        assert len(mock_websocket.sent_messages) == 1
        response = json.loads(mock_websocket.sent_messages[0])
        assert response['type'] == 'auth_success'
        assert response['user_id'] == user_id
    
    @pytest.mark.asyncio
    async def test_invalid_token_authentication(self, auth_middleware, mock_websocket):
        auth_message = json.dumps({"token": "invalid_token"})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock()
        
        await auth_middleware.on_connect(handler, mock_websocket)
        
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "format" in mock_websocket.close_reason.lower()
        
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_expired_token_authentication(self, secret_key, mock_websocket):
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            token_ttl=300,
            enable_ip_validation=False,
            rate_limit_attempts=5,
            rate_limit_window=60,
            max_tickets=1000,
            allowed_origins=None
        )
        
        mock_websocket._websocket.request.remote = ("10.0.0.99", 12345)
        mock_websocket._websocket.remote_address = ("10.0.0.99", 12345)
        
        user_id = "test_user"
        
        current_time = int(time.time())
        expired_time = current_time - 100
        
        header = SecureToken.encode_payload({
            "alg": "HS256",
            "typ": "JWT"
        })
        
        payload_data = {
            "sub": user_id,
            "iat": expired_time,
            "exp": expired_time + 10,
            "jti": "test_expired_middleware_ticket",
            "ip": None,
            "nonce": "test_nonce_middleware"
        }
        
        payload_encoded = SecureToken.encode_payload(payload_data)
        signature = SecureToken.create_signature(header, payload_encoded, secret_key)
        token = f"{header}.{payload_encoded}.{signature}"
        
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock()
        
        await auth_middleware.on_connect(handler, mock_websocket)
        
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "expired" in mock_websocket.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_replay_attack_protection(self, auth_middleware, mock_websocket):
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        mock_websocket._websocket.request.remote = (client_ip, 12345)
        mock_websocket._websocket.remote_address = (client_ip, 12345)
        
        token = auth_middleware.generate_token(user_id, client_ip)
        
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock(return_value="success")
        result = await auth_middleware.on_connect(handler, mock_websocket)
        
        assert result == "success"
        assert not mock_websocket.closed
        
        mock_websocket2 = MockWebSocket(remote_ip=client_ip)
        mock_websocket2.add_message(auth_message)
        
        handler2 = AsyncMock()
        await auth_middleware.on_connect(handler2, mock_websocket2)
        
        assert mock_websocket2.closed
        assert mock_websocket2.close_code == 4401
        assert "replay" in mock_websocket2.close_reason.lower()
        handler2.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_ip_validation_failure(self, auth_middleware, mock_websocket):
        user_id = "test_user"
        original_ip = "192.168.1.100"
        different_ip = "192.168.1.200"
        
        token = auth_middleware.generate_token(user_id, original_ip)
        
        mock_websocket = MockWebSocket(remote_ip=different_ip)
        auth_message = json.dumps({"token": token})
        mock_websocket.add_message(auth_message)
        
        handler = AsyncMock()
        await auth_middleware.on_connect(handler, mock_websocket)
        
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "mismatch" in mock_websocket.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_malformed_auth_message(self, auth_middleware, mock_websocket):
        malformed_messages = [
            "not_json",
            json.dumps({"wrong_field": "value"}),
            json.dumps({}),
            "",
        ]
        
        for i, message in enumerate(malformed_messages):
            mock_ws = MockWebSocket(remote_ip=f"192.168.1.{100 + i}")
            mock_ws.add_message(message)
            
            handler = AsyncMock()
            await auth_middleware.on_connect(handler, mock_ws)
            
            assert mock_ws.closed
            assert mock_ws.close_code == 4401
            assert "format" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, auth_middleware, mock_websocket):
        for i in range(3):
            mock_ws = MockWebSocket()
            mock_ws.add_message(json.dumps({"token": "invalid_token"}))
            
            handler = AsyncMock()
            await auth_middleware.on_connect(handler, mock_ws)
            
            assert mock_ws.closed
        
        mock_ws = MockWebSocket()
        mock_ws.add_message(json.dumps({"token": "any_token"}))
        
        handler = AsyncMock()
        await auth_middleware.on_connect(handler, mock_ws)
        
        assert mock_ws.closed
        assert mock_ws.close_code == 4429
        assert "rate limit" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_message_handling_unauthenticated(self, auth_middleware, mock_websocket):
        handler = AsyncMock()
        
        await auth_middleware.on_message(handler, mock_websocket)
        
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "required" in mock_websocket.close_reason.lower()
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_message_handling_authenticated(self, auth_middleware, mock_websocket):
        mock_websocket.context['authenticated'] = True
        mock_websocket.context['user_id'] = 'test_user'
        mock_websocket.context['auth_timestamp'] = time.time()
        
        handler = AsyncMock(return_value="message_handled")
        
        result = await auth_middleware.on_message(handler, mock_websocket)
        
        assert result == "message_handled"
        assert not mock_websocket.closed
        handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_session_timeout(self, auth_middleware, mock_websocket):
        mock_websocket.context['authenticated'] = True
        mock_websocket.context['user_id'] = 'test_user'
        mock_websocket.context['auth_timestamp'] = time.time() - 3700
        
        handler = AsyncMock()
        
        await auth_middleware.on_message(handler, mock_websocket)
        
        assert mock_websocket.closed
        assert mock_websocket.close_code == 4401
        assert "expired" in mock_websocket.close_reason.lower()
        handler.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_disconnect_handling(self, auth_middleware, mock_websocket):
        mock_websocket.context['user_id'] = 'test_user'
        
        handler = AsyncMock(return_value="disconnected")
        
        result = await auth_middleware.on_disconnect(handler, mock_websocket)
        
        assert result == "disconnected"
        handler.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_security_headers_validation(self, secret_key):
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            allowed_origins=["https://example.com", "https://app.example.com"]
        )
        
        mock_ws = MockWebSocket(headers={
            'origin': 'https://example.com',
            'user-agent': 'Mozilla/5.0 (compatible browser)'
        })
        
        assert auth_middleware._validate_security_headers(mock_ws) is True
        
        mock_ws2 = MockWebSocket(headers={
            'origin': 'https://malicious.com',
            'user-agent': 'Mozilla/5.0 (compatible browser)'
        })
        
        assert auth_middleware._validate_security_headers(mock_ws2) is False
        
        mock_ws3 = MockWebSocket(headers={
            'origin': 'https://example.com',
            'user-agent': 'bot'
        })
        
        assert auth_middleware._validate_security_headers(mock_ws3) is False
    
    @pytest.mark.asyncio
    async def test_auth_timeout_protection(self, secret_key):
        auth_middleware = AuthMiddleware(
            secret_key=secret_key,
            auth_timeout=0.1
        )
        
        mock_ws = MockWebSocket()
        
        handler = AsyncMock()
        
        result = await auth_middleware.on_connect(handler, mock_ws)
        
        assert result is None
        assert mock_ws.closed
        assert mock_ws.close_code == 4401
        assert "timeout" in mock_ws.close_reason.lower()
    
    @pytest.mark.asyncio
    async def test_ip_extractor_configurability(self, secret_key):
        auth_middleware = AuthMiddleware(secret_key=secret_key)
        
        mock_ws = MockWebSocket(headers={
            'x-forwarded-for': '192.168.1.100, 10.0.0.1',
            'x-real-ip': '192.168.1.200'
        })
        
        ip = auth_middleware._get_client_ip(mock_ws)
        assert ip == '192.168.1.100'
        
        mock_ws2 = MockWebSocket(headers={
            'x-real-ip': '192.168.1.200'
        })
        
        ip2 = auth_middleware._get_client_ip(mock_ws2)
        assert ip2 == '192.168.1.200'


class TestUtilityFunctions:
    def test_generate_auth_token_function(self, secret_key):
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        token = generate_auth_token(secret_key, user_id, client_ip, 300)
        
        payload = verify_auth_token(token, secret_key, client_ip)
        assert payload['sub'] == user_id
        assert payload['ip'] == client_ip
    
    def test_verify_auth_token_function(self, secret_key):
        user_id = "test_user"
        
        token = generate_auth_token(secret_key, user_id)
        
        payload = verify_auth_token(token, secret_key)
        assert payload['sub'] == user_id
        
        with pytest.raises(AuthenticationError):
            verify_auth_token("invalid_token", secret_key)


class TestSecurityScenarios:
    @pytest.mark.asyncio
    async def test_timing_attack_resistance(self, auth_middleware, mock_websocket):
        user_id = "test_user"
        valid_token = auth_middleware.generate_token(user_id)
        invalid_token = "invalid_token_with_similar_length_to_valid_one"
        
        mock_ws1 = MockWebSocket()
        mock_ws1.add_message(json.dumps({"token": valid_token}))
        
        start_time = time.time()
        await auth_middleware.on_connect(AsyncMock(), mock_ws1)
        valid_time = time.time() - start_time
        
        mock_ws2 = MockWebSocket()
        mock_ws2.add_message(json.dumps({"token": invalid_token}))
        
        start_time = time.time()
        await auth_middleware.on_connect(AsyncMock(), mock_ws2)
        invalid_time = time.time() - start_time
        
        time_ratio = max(valid_time, invalid_time) / min(valid_time, invalid_time)
        assert time_ratio < 20
    
    def test_token_collision_resistance(self, secret_key):
        user_id = "test_user"
        tokens = set()
        
        for _ in range(1000):
            token = SecureToken.generate(user_id, secret_key)
            assert token not in tokens, "Token collision detected!"
            tokens.add(token)
    
    def test_secret_key_requirements(self):
        weak_keys = [
            "",
            "short",
            "exactly_31_characters_long_here",
        ]
        
        for weak_key in weak_keys:
            with pytest.raises(ValueError, match="Secret key must be at least 32 characters"):
                AuthMiddleware(weak_key)
        
        valid_key = "a" * 32
        auth = AuthMiddleware(valid_key)
        assert auth.secret_key == valid_key
    
    @pytest.mark.asyncio
    async def test_concurrent_authentication_attempts(self, auth_middleware):
        user_id = "test_user"
        client_ip = "192.168.1.100"
        
        tokens = [auth_middleware.generate_token(user_id, client_ip) for _ in range(5)]
        
        async def authenticate_with_token(token):
            mock_ws = MockWebSocket(remote_ip=client_ip)
            mock_ws.add_message(json.dumps({"token": token}))
            handler = AsyncMock(return_value="success")
            return await auth_middleware.on_connect(handler, mock_ws)
        
        tasks = [authenticate_with_token(token) for token in tokens]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            assert result == "success"


if __name__ == "__main__":
    pytest.main([__file__]) 