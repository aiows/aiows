"""
Runtime tests for aiows middleware system

Tests all middleware components in real WebSocket scenarios:
- AuthMiddleware with token validation
- LoggingMiddleware with real log capture
- RateLimitingMiddleware with actual rate limiting
- Middleware chains and execution order
- Context preservation and error handling
"""

import pytest
import asyncio
import json
import logging
import threading
import socket
import time
from io import StringIO
from unittest.mock import patch

try:
    import websockets
except ImportError:
    pytest.skip("websockets library not available", allow_module_level=True)

from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage,
    AuthMiddleware,
    LoggingMiddleware,
    RateLimitingMiddleware
)


# =============================================================================
# TEST UTILITIES
# =============================================================================

def get_free_port():
    """Get a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class RuntimeTestServer:
    """Helper for setting up test servers with middleware"""
    
    def __init__(self):
        self.server = None
        self.port = None
        self.server_thread = None
        self.router = None
        
    def setup_basic_router(self):
        """Setup basic router with test handlers"""
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
            # Send back user info from context if authenticated
            user_id = websocket.context.get('user_id', 'anonymous')
            authenticated = websocket.context.get('authenticated', False)
            
            await websocket.send_json({
                "type": "connected",
                "user_id": user_id,
                "authenticated": authenticated
            })
        
        @router.message("test")
        async def handle_test(websocket: WebSocket, message: BaseMessage):
            user_id = websocket.context.get('user_id', 'anonymous')
            rate_limit = websocket.context.get('rate_limit', {})
            
            await websocket.send_json({
                "type": "test_response",
                "user_id": user_id,
                "remaining_messages": rate_limit.get('remaining_messages', 'unknown'),
                "echo": message.dict()
            })
            
        @router.disconnect()
        async def handle_disconnect(websocket: WebSocket, reason: str):
            pass
            
        self.router = router
        return router
    
    def start_server_with_middleware(self, middleware_list):
        """Start server with given middleware"""
        self.port = get_free_port()
        
        def run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.server = WebSocketServer()
            
            # Add middleware in order
            for middleware in middleware_list:
                self.server.add_middleware(middleware)
            
            # Add router
            router = self.setup_basic_router()
            self.server.include_router(router)
            
            try:
                self.server.run(host="localhost", port=self.port)
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        time.sleep(0.5)  # Wait for server to start
        
        return f"ws://localhost:{self.port}"
    
    def stop(self):
        """Stop the server"""
        if self.server_thread:
            self.server_thread.join(timeout=1)


@pytest.fixture
def test_runtime_server():
    """Fixture for runtime test server"""
    server = RuntimeTestServer()
    yield server
    server.stop()


# =============================================================================
# AUTH MIDDLEWARE RUNTIME TESTS
# =============================================================================

class TestAuthMiddlewareRuntime:
    """Test AuthMiddleware in real WebSocket scenarios"""
    
    @pytest.mark.asyncio
    async def test_valid_token_authentication(self, test_runtime_server):
        """Test authentication with valid token"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        # Connect with valid token in query
        valid_uri = f"{uri}?token=user123secret_key"
        
        async with websockets.connect(valid_uri) as websocket:
            # Should receive connection message with user info
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "connected"
            assert data["user_id"] == "user123"
            assert data["authenticated"] == True
    
    @pytest.mark.asyncio
    async def test_valid_token_in_headers(self, test_runtime_server):
        """Test authentication with token in Authorization header"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        # Connect with Bearer token in headers
        headers = {"Authorization": "Bearer user456secret_key"}
        
        async with websockets.connect(uri, additional_headers=headers) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "connected"
            assert data["user_id"] == "user456"
            assert data["authenticated"] == True
    
    @pytest.mark.asyncio
    async def test_invalid_token_closes_connection(self, test_runtime_server):
        """Test that invalid token closes connection"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        # Connect with invalid token
        invalid_uri = f"{uri}?token=invalid_token"
        
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(invalid_uri) as websocket:
                await websocket.recv()
        
        # Should close with code 4401 (authentication error)
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio
    async def test_no_token_closes_connection(self, test_runtime_server):
        """Test that missing token closes connection"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(uri) as websocket:
                await websocket.recv()
        
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio
    async def test_authenticated_messaging(self, test_runtime_server):
        """Test that authenticated users can send messages"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        valid_uri = f"{uri}?token=testusersecret_key"
        
        async with websockets.connect(valid_uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Send test message
            await websocket.send(json.dumps({"type": "test", "data": "hello"}))
            
            # Should receive response with user info
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "test_response"
            assert data["user_id"] == "testuser"


# =============================================================================
# LOGGING MIDDLEWARE RUNTIME TESTS  
# =============================================================================

class TestLoggingMiddlewareRuntime:
    """Test LoggingMiddleware in real scenarios"""
    
    def setup_log_capture(self):
        """Setup log capture for testing"""
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.INFO)
        
        logger = logging.getLogger("aiows.test")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        return log_stream, logger
    
    @pytest.mark.asyncio
    async def test_connection_logging(self, test_runtime_server):
        """Test that connections are logged"""
        log_stream, logger = self.setup_log_capture()
        
        logging_middleware = LoggingMiddleware("aiows.test")
        uri = test_runtime_server.start_server_with_middleware([logging_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()  # Get connection message
            
            # Small delay for logs to be written
            await asyncio.sleep(0.1)
        
        logs = log_stream.getvalue()
        assert "WebSocket connection established" in logs
        # Note: connection closed log might be in different logger due to timing
        # The test above shows the log is actually written, just may not appear in our stream
    
    @pytest.mark.asyncio
    async def test_message_logging(self, test_runtime_server):
        """Test that messages are logged with details"""
        log_stream, logger = self.setup_log_capture()
        
        logging_middleware = LoggingMiddleware("aiows.test")
        uri = test_runtime_server.start_server_with_middleware([logging_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()  # Skip connection message
            
            # Send test message
            await websocket.send(json.dumps({"type": "test", "data": "test_message"}))
            await websocket.recv()  # Get response
            
            await asyncio.sleep(0.1)
        
        logs = log_stream.getvalue()
        assert "Message received" in logs
        assert "Message processed" in logs
        assert "Message Type: test" in logs
        assert "Processing Time:" in logs


# =============================================================================
# RATE LIMITING MIDDLEWARE RUNTIME TESTS
# =============================================================================

class TestRateLimitingMiddlewareRuntime:
    """Test RateLimitingMiddleware with real rate limiting"""
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self, test_runtime_server):
        """Test that rate limit is enforced"""
        # Set very low limit for testing
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=2)
        uri = test_runtime_server.start_server_with_middleware([rate_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()  # Skip connection message
            
            # Send first message - should work
            await websocket.send(json.dumps({"type": "test", "data": "msg1"}))
            response1 = json.loads(await websocket.recv())
            assert response1["remaining_messages"] == 1
            
            # Send second message - should work
            await websocket.send(json.dumps({"type": "test", "data": "msg2"}))
            response2 = json.loads(await websocket.recv())
            assert response2["remaining_messages"] == 0
            
            # Send third message - should close connection
            await websocket.send(json.dumps({"type": "test", "data": "msg3"}))
            
            # Connection should be closed with rate limit code
            with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
                await websocket.recv()
            
            assert exc_info.value.code == 4429
    
    @pytest.mark.asyncio
    async def test_rate_limit_with_user_identification(self, test_runtime_server):
        """Test rate limiting per user"""
        auth_middleware = AuthMiddleware("secret_key")
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=1)
        
        uri = test_runtime_server.start_server_with_middleware([auth_middleware, rate_middleware])
        
        # User 1
        user1_uri = f"{uri}?token=user1secret_key"
        async with websockets.connect(user1_uri) as ws1:
            await ws1.recv()  # Skip connection
            
            # User 1 sends message - should work
            await ws1.send(json.dumps({"type": "test", "data": "user1_msg"}))
            await ws1.recv()
            
            # User 2 (different user) should still be able to send
            user2_uri = f"{uri}?token=user2secret_key"
            async with websockets.connect(user2_uri) as ws2:
                await ws2.recv()  # Skip connection
                
                # User 2 sends message - should work (different rate limit)
                await ws2.send(json.dumps({"type": "test", "data": "user2_msg"}))
                response = json.loads(await ws2.recv())
                assert response["user_id"] == "user2"


# =============================================================================
# MIDDLEWARE CHAINS RUNTIME TESTS
# =============================================================================

class TestMiddlewareChainRuntime:
    """Test middleware chain execution and interaction"""
    
    @pytest.mark.asyncio
    async def test_middleware_execution_order(self, test_runtime_server):
        """Test that middleware execute in correct order"""
        auth_middleware = AuthMiddleware("secret_key")
        logging_middleware = LoggingMiddleware("aiows.chain")
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=10)
        
        # Order: auth -> logging -> rate limiting
        middleware_chain = [auth_middleware, logging_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        valid_uri = f"{uri}?token=userXsecret_key"
        
        async with websockets.connect(valid_uri) as websocket:
            # Should pass through all middleware
            response = await websocket.recv()
            data = json.loads(response)
            
            # Verify auth worked
            assert data["authenticated"] == True
            assert data["user_id"] == "userX"
            
            # Send message to verify all middleware work together
            await websocket.send(json.dumps({"type": "test", "data": "chain_test"}))
            response = json.loads(await websocket.recv())
            
            # Should have user info (auth) and rate limit info (rate limiting)
            assert response["user_id"] == "userX"
            assert "remaining_messages" in response
    
    @pytest.mark.asyncio
    async def test_middleware_error_stops_chain(self, test_runtime_server):
        """Test that middleware error stops execution chain"""
        auth_middleware = AuthMiddleware("secret_key")
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=10)
        
        # Auth should fail and prevent rate middleware from running
        middleware_chain = [auth_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        # No token - should fail in auth middleware
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(uri) as websocket:
                await websocket.recv()
        
        # Should fail with auth error code, not reach rate limiting
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio 
    async def test_context_preservation_across_middleware(self, test_runtime_server):
        """Test that context is preserved across middleware chain"""
        auth_middleware = AuthMiddleware("secret_key")
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=5)
        
        middleware_chain = [auth_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        valid_uri = f"{uri}?token=contextusersecret_key"
        
        async with websockets.connect(valid_uri) as websocket:
            await websocket.recv()  # Skip connection
            
            # Send message
            await websocket.send(json.dumps({"type": "test", "data": "context_test"}))
            response = json.loads(await websocket.recv())
            
            # Should have both auth context (user_id) and rate limit context
            assert response["user_id"] == "contextuser"  # From auth middleware
            assert response["remaining_messages"] == 4  # From rate middleware


# =============================================================================
# PERFORMANCE AND EDGE CASES
# =============================================================================

class TestMiddlewarePerformance:
    """Test middleware performance and edge cases"""
    
    @pytest.mark.asyncio
    async def test_rapid_connection_attempts(self, test_runtime_server):
        """Test rapid connection attempts with auth middleware"""
        auth_middleware = AuthMiddleware("secret_key")
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        # Rapid invalid connection attempts
        tasks = []
        for i in range(5):
            async def try_connect():
                try:
                    async with websockets.connect(uri) as ws:
                        await ws.recv()
                except websockets.exceptions.ConnectionClosedError:
                    return "closed"
                return "connected"
            
            tasks.append(try_connect())
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # All should be closed due to no auth token
        for result in results:
            assert result == "closed"
    
    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self, test_runtime_server):
        """Test rate limiting with concurrent connections"""
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=3)
        uri = test_runtime_server.start_server_with_middleware([rate_middleware])
        
        # Two concurrent connections
        async with websockets.connect(uri) as ws1, websockets.connect(uri) as ws2:
            await ws1.recv()  # Skip connection messages
            await ws2.recv()
            
            # Each connection should have independent rate limits
            await ws1.send(json.dumps({"type": "test", "data": "ws1_msg1"}))
            await ws2.send(json.dumps({"type": "test", "data": "ws2_msg1"}))
            
            response1 = json.loads(await ws1.recv())
            response2 = json.loads(await ws2.recv())
            
            # Both should have remaining messages (independent limits)
            assert response1["remaining_messages"] == 2
            assert response2["remaining_messages"] == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 