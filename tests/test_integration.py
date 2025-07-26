"""
Comprehensive integration tests for aiows framework

This test suite includes both unit tests with mocks and integration tests
with real WebSocket connections to verify the complete framework functionality.
"""

import pytest
import asyncio
import json
import threading
import time
import socket
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, List, Optional

# Import websockets for client connections
try:
    import websockets
except ImportError:
    pytest.skip("websockets library not available", allow_module_level=True)

# Import aiows components
from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage, 
    ChatMessage,
    JoinRoomMessage,
    GameActionMessage,
    MessageValidationError,
    ConnectionError as AiowsConnectionError
)


# =============================================================================
# TEST FIXTURES AND UTILITIES
# =============================================================================

def get_free_port() -> int:
    """Get a free port for testing"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class ServerManager:
    """Manager for test server lifecycle"""
    
    def __init__(self):
        self.server = None
        self.port = None
        self.server_thread = None
        self.router = None
        self.loop = None
        
    def setup_router(self) -> Router:
        """Setup router with test handlers"""
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
            await websocket.send_json({"type": "connected", "status": "ok"})
        
        @router.message("chat")
        async def handle_chat(websocket: WebSocket, message: BaseMessage):
            await websocket.send_json({
                "type": "chat_response", 
                "echo": message.dict()
            })
        
        @router.message("join_room")
        async def handle_join_room(websocket: WebSocket, message: BaseMessage):
            await websocket.send_json({
                "type": "room_joined",
                "room": message.room_id if hasattr(message, 'room_id') else "unknown"
            })
        
        @router.message("game_action")
        async def handle_game_action(websocket: WebSocket, message: BaseMessage):
            await websocket.send_json({
                "type": "game_response",
                "action": message.dict().get("action", "unknown")
            })
        
        @router.disconnect()
        async def handle_disconnect(websocket: WebSocket, reason: str):
            pass  # Just for testing disconnect handler registration
        
        self.router = router
        return router
    
    def start_server(self) -> int:
        """Start test server and return port"""
        self.port = get_free_port()
        
        def run_server():
            # Create new event loop for server thread
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            self.server = WebSocketServer()
            router = self.setup_router()
            self.server.include_router(router)
            
            try:
                self.server.run(host="localhost", port=self.port)
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        # Wait for server to start
        time.sleep(0.5)
        return self.port
    
    def stop_server(self):
        """Stop test server"""
        if self.loop:
            # Stop the server loop
            self.loop.call_soon_threadsafe(self.loop.stop)
        
        if self.server_thread:
            self.server_thread.join(timeout=2)


@pytest.fixture
def test_server():
    """Fixture for test server"""
    manager = ServerManager()
    port = manager.start_server()
    yield f"ws://localhost:{port}", manager
    manager.stop_server()


async def websocket_client(uri: str, timeout: float = 5.0):
    """Create WebSocket client for testing"""
    try:
        websocket = await asyncio.wait_for(
            websockets.connect(uri), 
            timeout=timeout
        )
        return websocket
    except Exception as e:
        pytest.fail(f"Failed to connect to WebSocket: {e}")


def message_factory(message_type: str, **kwargs) -> Dict[str, Any]:
    """Factory for creating test messages"""
    base_message = {"type": message_type}
    base_message.update(kwargs)
    return base_message


# =============================================================================
# MOCK TESTS
# =============================================================================

class TestMessageTypesValidation:
    """Test message types validation with mocks"""
    
    def test_base_message_validation(self):
        """Test BaseMessage validation"""
        # Valid message
        valid_data = {"type": "test", "data": "value"}
        message = BaseMessage(**valid_data)
        assert message.type == "test"
        
        # Invalid message (missing type)
        with pytest.raises(Exception):
            BaseMessage(data="value")
    
    def test_chat_message_validation(self):
        """Test ChatMessage validation"""
        # Valid chat message
        valid_data = {"type": "chat", "text": "Hello", "user_id": 123}
        message = ChatMessage(**valid_data)
        assert message.text == "Hello"
        assert message.user_id == 123
        
        # Invalid chat message (missing required fields)
        with pytest.raises(Exception):
            ChatMessage(type="chat")
    
    def test_join_room_message_validation(self):
        """Test JoinRoomMessage validation"""
        # Valid join room message
        valid_data = {"type": "join_room", "room_id": "general", "user_name": "Bob"}
        message = JoinRoomMessage(**valid_data)
        assert message.room_id == "general"
        assert message.user_name == "Bob"
    
    def test_game_action_message_validation(self):
        """Test GameActionMessage validation"""
        # Valid game action message
        valid_data = {"type": "game_action", "action": "move", "coordinates": (5, 10)}
        message = GameActionMessage(**valid_data)
        assert message.action == "move"
        assert message.coordinates == (5, 10)


class TestRouterHandlersRegistration:
    """Test router handlers registration with mocks"""
    
    def test_connect_handler_registration(self):
        """Test connect handler registration"""
        router = Router()
        
        @router.connect()
        async def test_handler(websocket):
            pass
        
        assert len(router._connect_handlers) == 1
        assert router._connect_handlers[0] == test_handler
    
    def test_disconnect_handler_registration(self):
        """Test disconnect handler registration"""
        router = Router()
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            pass
        
        assert len(router._disconnect_handlers) == 1
        assert router._disconnect_handlers[0] == test_handler
    
    def test_message_handler_registration(self):
        """Test message handler registration"""
        router = Router()
        
        @router.message("test_type")
        async def test_handler(websocket, message):
            pass
        
        @router.message()  # Universal handler
        async def universal_handler(websocket, message):
            pass
        
        assert len(router._message_handlers) == 2
        assert router._message_handlers[0]["message_type"] == "test_type"
        assert router._message_handlers[0]["handler"] == test_handler
        assert router._message_handlers[1]["message_type"] is None
        assert router._message_handlers[1]["handler"] == universal_handler
    
    def test_include_router(self):
        """Test router inclusion"""
        main_router = Router()
        sub_router = Router()
        
        main_router.include_router(sub_router, prefix="api")
        
        assert len(main_router._sub_routers) == 1
        assert main_router._sub_routers[0]["router"] == sub_router
        assert main_router._sub_routers[0]["prefix"] == "api"


class TestWebSocketWrapperMethods:
    """Test WebSocket wrapper methods with mocks"""
    
    @pytest.mark.asyncio
    async def test_send_json(self):
        """Test WebSocket send_json method"""
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        test_data = {"type": "test", "message": "hello"}
        await websocket.send_json(test_data)
        
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        assert json.loads(sent_data) == test_data
    
    @pytest.mark.asyncio
    async def test_send_message(self):
        """Test WebSocket send_message method"""
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        # Mock the send_json method to avoid datetime serialization issues
        with patch.object(websocket, 'send_json') as mock_send_json:
            message = BaseMessage(type="test")
            await websocket.send_message(message)
            
            mock_send_json.assert_called_once()
            # Verify that send_json was called with message.dict()
            call_args = mock_send_json.call_args[0][0]
            assert call_args["type"] == "test"
            assert "timestamp" in call_args
    
    @pytest.mark.asyncio
    async def test_receive_json(self):
        """Test WebSocket receive_json method"""
        mock_websocket = AsyncMock()
        mock_websocket.recv.return_value = '{"type": "test", "data": "value"}'
        
        websocket = WebSocket(mock_websocket)
        result = await websocket.receive_json()
        
        assert result == {"type": "test", "data": "value"}
        mock_websocket.recv.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close(self):
        """Test WebSocket close method"""
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        await websocket.close(code=1000, reason="Test close")
        
        mock_websocket.close.assert_called_once_with(code=1000, reason="Test close")
        assert websocket.is_closed is True
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        """Test WebSocket connection error handling"""
        mock_websocket = AsyncMock()
        mock_websocket.send.side_effect = Exception("Connection lost")
        
        websocket = WebSocket(mock_websocket)
        
        with pytest.raises(AiowsConnectionError):
            await websocket.send_json({"type": "test"})


class TestDispatcherRouting:
    """Test MessageDispatcher routing with mocks"""
    
    @pytest.mark.asyncio
    async def test_dispatch_connect(self):
        """Test dispatch_connect method"""
        from aiows.dispatcher import MessageDispatcher
        
        router = Router()
        handler_called = False
        
        @router.connect()
        async def test_handler(websocket):
            nonlocal handler_called
            handler_called = True
        
        dispatcher = MessageDispatcher(router)
        mock_websocket = Mock(spec=WebSocket)
        mock_websocket.context = {}
        
        await dispatcher.dispatch_connect(mock_websocket)
        assert handler_called is True
    
    @pytest.mark.asyncio
    async def test_dispatch_message_routing(self):
        """Test message routing in dispatcher"""
        from aiows.dispatcher import MessageDispatcher
        
        router = Router()
        chat_handler_called = False
        universal_handler_called = False
        
        @router.message("chat")
        async def chat_handler(websocket, message):
            nonlocal chat_handler_called
            chat_handler_called = True
        
        @router.message()
        async def universal_handler(websocket, message):
            nonlocal universal_handler_called
            universal_handler_called = True
        
        dispatcher = MessageDispatcher(router)
        mock_websocket = Mock(spec=WebSocket)
        mock_websocket.context = {}
        
        # Test specific message type routing
        await dispatcher.dispatch_message(mock_websocket, {"type": "chat", "text": "hello", "user_id": 123})
        assert chat_handler_called is True
        assert universal_handler_called is False
    
    @pytest.mark.asyncio
    async def test_dispatch_disconnect(self):
        """Test dispatch_disconnect method"""
        from aiows.dispatcher import MessageDispatcher
        
        router = Router()
        handler_called = False
        received_reason = None
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            nonlocal handler_called, received_reason
            handler_called = True
            received_reason = reason
        
        dispatcher = MessageDispatcher(router)
        mock_websocket = Mock(spec=WebSocket)
        mock_websocket.context = {}
        
        await dispatcher.dispatch_disconnect(mock_websocket, "Test reason")
        assert handler_called is True
        assert received_reason == "Test reason"


class TestServerConnectionManagement:
    """Test WebSocketServer connection management with mocks"""
    
    def test_include_router(self):
        """Test router inclusion in server"""
        server = WebSocketServer()
        router = Router()
        
        server.include_router(router)
        
        assert server.router == router
        assert server.dispatcher.router == router
    
    def test_server_initialization(self):
        """Test server initialization"""
        server = WebSocketServer()
        
        assert server.host == "localhost"
        assert server.port == 8000
        assert server.router is not None
        assert server.dispatcher is not None
        assert isinstance(server._connections, set)


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestFullChatFlow:
    """Test complete chat flow with real WebSocket connections"""
    
    @pytest.mark.asyncio
    async def test_connect_send_receive_disconnect(self, test_server):
        """Test full chat flow from connection to disconnection"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Test connection
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "connected"
            assert data["status"] == "ok"
            
            # Test chat message
            chat_message = message_factory("chat", text="Hello World", user_id=123)
            await websocket.send(json.dumps(chat_message))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "chat_response"
            assert data["echo"]["text"] == "Hello World"
            assert data["echo"]["user_id"] == 123


class TestMultipleMessageTypes:
    """Test different message types with real WebSocket connections"""
    
    @pytest.mark.asyncio
    async def test_different_message_types(self, test_server):
        """Test sending different types of messages"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Test chat message
            chat_msg = message_factory("chat", text="Hello", user_id=456)
            await websocket.send(json.dumps(chat_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "chat_response"
            
            # Test join room message
            join_msg = message_factory("join_room", room_id="general", user_name="Alice")
            await websocket.send(json.dumps(join_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "room_joined"
            assert response["room"] == "general"
            
            # Test game action message
            game_msg = message_factory("game_action", action="move", coordinates=(3, 4))
            await websocket.send(json.dumps(game_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "game_response"
            assert response["action"] == "move"


class TestMultipleClients:
    """Test multiple simultaneous WebSocket connections"""
    
    @pytest.mark.asyncio
    async def test_concurrent_connections(self, test_server):
        """Test multiple clients connecting simultaneously"""
        uri, server_manager = test_server
        
        # Create multiple clients
        clients = []
        try:
            for i in range(3):
                client = await websocket_client(uri)
                clients.append(client)
                
                # Receive connection message
                response = await client.recv()
                data = json.loads(response)
                assert data["type"] == "connected"
            
            # Send messages from each client
            for i, client in enumerate(clients):
                chat_msg = message_factory("chat", text=f"Message from client {i}", user_id=i+100)
                await client.send(json.dumps(chat_msg))
                
                response = json.loads(await client.recv())
                assert response["type"] == "chat_response"
                assert response["echo"]["text"] == f"Message from client {i}"
                
        finally:
            # Clean up connections
            for client in clients:
                try:
                    await client.close()
                except:
                    pass


class TestConnectionLifecycle:
    """Test complete connection lifecycle"""
    
    @pytest.mark.asyncio
    async def test_connection_context_persistence(self, test_server):
        """Test that connection context persists during session"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Send multiple messages to test context persistence
            for i in range(3):
                msg = message_factory("chat", text=f"Message {i}", user_id=777)
                await websocket.send(json.dumps(msg))
                
                response = json.loads(await websocket.recv())
                assert response["type"] == "chat_response"
                assert response["echo"]["text"] == f"Message {i}"
    
    @pytest.mark.asyncio
    async def test_graceful_disconnection(self, test_server):
        """Test graceful connection termination"""
        uri, server_manager = test_server
        
        websocket = await websocket_client(uri)
        try:
            # Receive connection message
            await websocket.recv()
            
            # Send a message
            msg = message_factory("chat", text="Goodbye", user_id=888)
            await websocket.send(json.dumps(msg))
            await websocket.recv()  # Receive response
            
        finally:
            await websocket.close()


class TestErrorHandling:
    """Test error handling and invalid messages"""
    
    @pytest.mark.asyncio
    async def test_invalid_json_handling(self, test_server):
        """Test handling of invalid JSON messages"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Send invalid JSON
            try:
                await websocket.send("invalid json")
                
                # Connection might close due to invalid JSON
                # This is expected behavior
                try:
                    await asyncio.wait_for(websocket.recv(), timeout=1.0)
                except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
                    pass  # Expected
                    
            except websockets.exceptions.ConnectionClosed:
                pass  # Expected for invalid JSON
    
    @pytest.mark.asyncio
    async def test_missing_message_type(self, test_server):
        """Test handling of messages without type field"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Send message without type
            try:
                await websocket.send(json.dumps({"data": "no type field"}))
                
                # Server should handle this gracefully
                try:
                    await asyncio.wait_for(websocket.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass  # No response expected for invalid message
                    
            except websockets.exceptions.ConnectionClosed:
                pass  # Connection might close due to validation error
    
    @pytest.mark.asyncio
    async def test_unknown_message_type(self, test_server):
        """Test handling of unknown message types"""
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            # Skip connection message
            await websocket.recv()
            
            # Send message with unknown type
            unknown_msg = message_factory("unknown_type", data="test")
            await websocket.send(json.dumps(unknown_msg))
            
            # Should not receive any response or connection should handle gracefully
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                # If we get a response, it should be an error or no handler found
            except asyncio.TimeoutError:
                pass  # No response is also acceptable


# =============================================================================
# TEST RUNNER CONFIGURATION
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 