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
from aiows.middleware.auth import generate_auth_token

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
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
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
        self.port = get_free_port()
        
        def run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.server = WebSocketServer()
            
            for middleware in middleware_list:
                self.server.add_middleware(middleware)
            
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
        if self.server_thread:
            self.server_thread.join(timeout=1)

@pytest.fixture
def test_runtime_server():
    server = RuntimeTestServer()
    yield server
    server.stop()

class TestAuthMiddlewareRuntime:
    
    @pytest.mark.asyncio
    async def test_valid_token_authentication(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user123",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        valid_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(valid_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "connected"
            assert data["user_id"] == "user123"
            assert data["authenticated"] == True
    
    @pytest.mark.asyncio
    async def test_valid_token_in_headers(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user456",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        headers = {"Authorization": f"Bearer {jwt_token}"}
        
        async with websockets.connect(uri, additional_headers=headers) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "connected"
            assert data["user_id"] == "user456"
            assert data["authenticated"] == True
    
    @pytest.mark.asyncio
    async def test_invalid_token_closes_connection(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=1)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        invalid_uri = f"{uri}?token=invalid_token"
        
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(invalid_uri) as websocket:
                await websocket.recv()
        
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio
    async def test_no_token_closes_connection(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=1)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(uri) as websocket:
                await websocket.recv()
        
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio
    async def test_authenticated_messaging(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
        jwt_token = generate_auth_token(
            user_id="testuser",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        valid_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(valid_uri) as websocket:
            await websocket.recv()
            await websocket.send(json.dumps({"type": "test", "data": "hello"}))
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["type"] == "test_response"
            assert data["user_id"] == "testuser"

class TestLoggingMiddlewareRuntime:
    
    def setup_log_capture(self):
        log_stream = StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.INFO)
        
        logger = logging.getLogger("aiows.test")
        logger.setLevel(logging.INFO)
        logger.addHandler(handler)
        
        return log_stream, logger
    
    @pytest.mark.asyncio
    async def test_connection_logging(self, test_runtime_server):
        log_stream, logger = self.setup_log_capture()
        
        logging_middleware = LoggingMiddleware("aiows.test")
        uri = test_runtime_server.start_server_with_middleware([logging_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()
            await asyncio.sleep(0.1)
        
        logs = log_stream.getvalue()
        assert "WebSocket connection established" in logs
    
    @pytest.mark.asyncio
    async def test_message_logging(self, test_runtime_server):
        log_stream, logger = self.setup_log_capture()
        
        logging_middleware = LoggingMiddleware("aiows.test")
        uri = test_runtime_server.start_server_with_middleware([logging_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()
            await websocket.send(json.dumps({"type": "test", "data": "test_message"}))
            await websocket.recv()
            await asyncio.sleep(0.1)
        
        logs = log_stream.getvalue()
        assert "Message received" in logs
        assert "Message processed" in logs
        # New secure logging middleware uses structured logging with simpler messages
        # The detailed info is available in structured_data when JSON format is enabled

class TestRateLimitingMiddlewareRuntime:
    
    @pytest.mark.asyncio
    async def test_rate_limit_enforcement(self, test_runtime_server):
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=2)
        uri = test_runtime_server.start_server_with_middleware([rate_middleware])
        
        async with websockets.connect(uri) as websocket:
            await websocket.recv()
            await websocket.send(json.dumps({"type": "test", "data": "msg1"}))
            response1 = json.loads(await websocket.recv())
            assert response1["remaining_messages"] == 1
            
            await websocket.send(json.dumps({"type": "test", "data": "msg2"}))
            response2 = json.loads(await websocket.recv())
            assert response2["remaining_messages"] == 0
            
            await websocket.send(json.dumps({"type": "test", "data": "msg3"}))
            
            with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
                await websocket.recv()
            
            assert exc_info.value.code == 4429
    
    @pytest.mark.asyncio
    async def test_rate_limit_with_user_identification(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=1)
        
        uri = test_runtime_server.start_server_with_middleware([auth_middleware, rate_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user1",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        valid_uri = f"{uri}?token={jwt_token}"
        async with websockets.connect(valid_uri) as ws1:
            await ws1.recv()
            await ws1.send(json.dumps({"type": "test", "data": "user1_msg"}))
            await ws1.recv()
            
        jwt_token = generate_auth_token(
            user_id="user2",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        user2_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(user2_uri) as ws2:
            await ws2.recv()
            await ws2.send(json.dumps({"type": "test", "data": "user2_msg"}))
            response = json.loads(await ws2.recv())
            assert response["user_id"] == "user2"

class TestMiddlewareChainRuntime:
    
    @pytest.mark.asyncio
    async def test_middleware_execution_order(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        logging_middleware = LoggingMiddleware("aiows.chain")
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=10)
        
        middleware_chain = [auth_middleware, logging_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        jwt_token = generate_auth_token(
            user_id="userX",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        valid_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(valid_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["authenticated"] == True
            assert data["user_id"] == "userX"
            
            await websocket.send(json.dumps({"type": "test", "data": "chain_test"}))
            response = json.loads(await websocket.recv())
            
            assert response["user_id"] == "userX"
            assert "remaining_messages" in response
    
    @pytest.mark.asyncio
    async def test_middleware_error_stops_chain(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=1)
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=10)
        
        middleware_chain = [auth_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        with pytest.raises(websockets.exceptions.ConnectionClosedError) as exc_info:
            async with websockets.connect(uri) as websocket:
                await websocket.recv()
        
        assert exc_info.value.code == 4401
    
    @pytest.mark.asyncio 
    async def test_context_preservation_across_middleware(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=5)
        
        middleware_chain = [auth_middleware, rate_middleware]
        uri = test_runtime_server.start_server_with_middleware(middleware_chain)
        
        jwt_token = generate_auth_token(
            user_id="contextuser",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        valid_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(valid_uri) as websocket:
            await websocket.recv()
            await websocket.send(json.dumps({"type": "test", "data": "context_test"}))
            response = json.loads(await websocket.recv())
            
            assert response["user_id"] == "contextuser"
            assert response["remaining_messages"] == 4

class TestMiddlewarePerformance:
    
    @pytest.mark.asyncio
    async def test_rapid_connection_attempts(self, test_runtime_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=1)
        uri = test_runtime_server.start_server_with_middleware([auth_middleware])
        
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
        
        for result in results:
            assert result == "closed"
    
    @pytest.mark.asyncio
    async def test_concurrent_rate_limiting(self, test_runtime_server):
        rate_middleware = RateLimitingMiddleware(max_messages_per_minute=3)
        uri = test_runtime_server.start_server_with_middleware([rate_middleware])
        
        async with websockets.connect(uri) as ws1, websockets.connect(uri) as ws2:
            await ws1.recv()
            await ws2.recv()
            
            await ws1.send(json.dumps({"type": "test", "data": "ws1_msg1"}))
            await ws2.send(json.dumps({"type": "test", "data": "ws2_msg1"}))
            
            response1 = json.loads(await ws1.recv())
            response2 = json.loads(await ws2.recv())
            
            assert response1["remaining_messages"] == 2
            assert response2["remaining_messages"] == 2

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 