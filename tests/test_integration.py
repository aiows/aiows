import pytest
import asyncio
import json
import threading
import time
import socket
import weakref
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

try:
    import websockets
except ImportError:
    pytest.skip("websockets library not available", allow_module_level=True)

from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage, 
    ChatMessage,
    JoinRoomMessage,
    GameActionMessage,
    ConnectionError as AiowsConnectionError
)

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

class ServerManager:
    def __init__(self):
        self.server = None
        self.port = None
        self.server_thread = None
        self.router = None
        self.loop = None
        
    def setup_router(self) -> Router:
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
            pass
        
        self.router = router
        return router
    
    def start_server(self) -> int:
        self.port = get_free_port()
        
        def run_server():
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
        
        time.sleep(0.5)
        return self.port
    
    def stop_server(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        
        if self.server_thread:
            self.server_thread.join(timeout=2)

@pytest.fixture
def test_server():
    manager = ServerManager()
    port = manager.start_server()
    yield f"ws://localhost:{port}", manager
    manager.stop_server()

async def websocket_client(uri: str, timeout: float = 5.0):
    try:
        websocket = await asyncio.wait_for(
            websockets.connect(uri), 
            timeout=timeout
        )
        return websocket
    except Exception as e:
        pytest.fail(f"Failed to connect to WebSocket: {e}")

def message_factory(message_type: str, **kwargs) -> Dict[str, Any]:
    base_message = {"type": message_type}
    base_message.update(kwargs)
    return base_message

class TestMessageTypesValidation:
    def test_base_message_validation(self):
        valid_data = {"type": "test", "data": "value"}
        message = BaseMessage(**valid_data)
        assert message.type == "test"
        
        with pytest.raises(Exception):
            BaseMessage(data="value")
    
    def test_chat_message_validation(self):
        valid_data = {"type": "chat", "text": "Hello", "user_id": 123}
        message = ChatMessage(**valid_data)
        assert message.text == "Hello"
        assert message.user_id == 123
        
        with pytest.raises(Exception):
            ChatMessage(type="chat")
    
    def test_join_room_message_validation(self):
        valid_data = {"type": "join_room", "room_id": "general", "user_name": "Bob"}
        message = JoinRoomMessage(**valid_data)
        assert message.room_id == "general"
        assert message.user_name == "Bob"
    
    def test_game_action_message_validation(self):
        valid_data = {"type": "game_action", "action": "move", "coordinates": (5, 10)}
        message = GameActionMessage(**valid_data)
        assert message.action == "move"
        assert message.coordinates == (5, 10)

class TestRouterHandlersRegistration:
    def test_connect_handler_registration(self):
        router = Router()
        
        @router.connect()
        async def test_handler(websocket):
            pass
        
        assert len(router._connect_handlers) == 1
        assert router._connect_handlers[0] == test_handler
    
    def test_disconnect_handler_registration(self):
        router = Router()
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            pass
        
        assert len(router._disconnect_handlers) == 1
        assert router._disconnect_handlers[0] == test_handler
    
    def test_message_handler_registration(self):
        router = Router()
        
        @router.message("test_type")
        async def test_handler(websocket, message):
            pass
        
        @router.message()
        async def universal_handler(websocket, message):
            pass
        
        assert len(router._message_handlers) == 2
        assert router._message_handlers[0]["message_type"] == "test_type"
        assert router._message_handlers[0]["handler"] == test_handler
        assert router._message_handlers[1]["message_type"] is None
        assert router._message_handlers[1]["handler"] == universal_handler
    
    def test_include_router(self):
        main_router = Router()
        sub_router = Router()
        
        main_router.include_router(sub_router, prefix="api")
        
        assert len(main_router._sub_routers) == 1
        assert main_router._sub_routers[0]["router"] == sub_router
        assert main_router._sub_routers[0]["prefix"] == "api"

class TestWebSocketWrapperMethods:
    
    @pytest.mark.asyncio
    async def test_send_json(self):
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        test_data = {"type": "test", "message": "hello"}
        await websocket.send_json(test_data)
        
        mock_websocket.send.assert_called_once()
        sent_data = mock_websocket.send.call_args[0][0]
        assert json.loads(sent_data) == test_data
    
    @pytest.mark.asyncio
    async def test_send_message(self):
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        with patch.object(websocket, 'send_json') as mock_send_json:
            message = BaseMessage(type="test")
            await websocket.send_message(message)
            
            mock_send_json.assert_called_once()
            call_args = mock_send_json.call_args[0][0]
            assert call_args["type"] == "test"
            assert "timestamp" in call_args
    
    @pytest.mark.asyncio
    async def test_receive_json(self):
        mock_websocket = AsyncMock()
        mock_websocket.recv.return_value = '{"type": "test", "data": "value"}'
        
        websocket = WebSocket(mock_websocket)
        result = await websocket.receive_json()
        
        assert result == {"type": "test", "data": "value"}
        mock_websocket.recv.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_close(self):
        mock_websocket = AsyncMock()
        websocket = WebSocket(mock_websocket)
        
        await websocket.close(code=1000, reason="Test close")
        
        mock_websocket.close.assert_called_once_with(code=1000, reason="Test close")
        assert websocket.is_closed is True
    
    @pytest.mark.asyncio
    async def test_connection_error_handling(self):
        mock_websocket = AsyncMock()
        mock_websocket.send.side_effect = Exception("Connection lost")
        
        websocket = WebSocket(mock_websocket)
        
        with pytest.raises(AiowsConnectionError):
            await websocket.send_json({"type": "test"})
    
    def test_remote_address_property(self):
        mock_websocket = Mock()
        mock_websocket.remote_address = ('127.0.0.1', 12345)
        
        websocket = WebSocket(mock_websocket)
        assert websocket.remote_address == ('127.0.0.1', 12345)
        
        mock_websocket2 = Mock(spec=[])
        
        websocket2 = WebSocket(mock_websocket2)
        assert websocket2.remote_address == ('unknown', 0)
        
        class SimpleWebSocket:
            pass
        
        simple_ws = SimpleWebSocket()
        websocket3 = WebSocket(simple_ws)
        assert websocket3.remote_address == ('unknown', 0)

class TestDispatcherRouting:
    
    @pytest.mark.asyncio
    async def test_dispatch_connect(self):
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
        
        await dispatcher.dispatch_message(mock_websocket, {"type": "chat", "text": "hello", "user_id": 123})
        assert chat_handler_called is True
        assert universal_handler_called is False
    
    @pytest.mark.asyncio
    async def test_dispatch_disconnect(self):
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
    
    def test_include_router(self):
        server = WebSocketServer()
        router = Router()
        
        server.include_router(router)
        
        assert server.router == router
        assert server.dispatcher.router == router
    
    def test_server_initialization(self):
        server = WebSocketServer()
        
        assert server.host == "localhost"
        assert server.port == 8000
        assert server.router is not None
        assert server.dispatcher is not None
        assert isinstance(server._connections, set)

class TestFullChatFlow:
    
    @pytest.mark.asyncio
    async def test_connect_send_receive_disconnect(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "connected"
            assert data["status"] == "ok"
            
            chat_message = message_factory("chat", text="Hello World", user_id=123)
            await websocket.send(json.dumps(chat_message))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "chat_response"
            assert data["echo"]["text"] == "Hello World"
            assert data["echo"]["user_id"] == 123

class TestMultipleMessageTypes:
    
    @pytest.mark.asyncio
    async def test_different_message_types(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            await websocket.recv()
            
            chat_msg = message_factory("chat", text="Hello", user_id=456)
            await websocket.send(json.dumps(chat_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "chat_response"
            
            join_msg = message_factory("join_room", room_id="general", user_name="Alice")
            await websocket.send(json.dumps(join_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "room_joined"
            assert response["room"] == "general"
            
            game_msg = message_factory("game_action", action="move", coordinates=(3, 4))
            await websocket.send(json.dumps(game_msg))
            response = json.loads(await websocket.recv())
            assert response["type"] == "game_response"
            assert response["action"] == "move"

class TestMultipleClients:
    
    @pytest.mark.asyncio
    async def test_concurrent_connections(self, test_server):
        uri, server_manager = test_server
        
        clients = []
        try:
            for i in range(3):
                client = await websocket_client(uri)
                clients.append(client)
                
                response = await client.recv()
                data = json.loads(response)
                assert data["type"] == "connected"
            
            for i, client in enumerate(clients):
                chat_msg = message_factory("chat", text=f"Message from client {i}", user_id=i+100)
                await client.send(json.dumps(chat_msg))
                
                response = json.loads(await client.recv())
                assert response["type"] == "chat_response"
                assert response["echo"]["text"] == f"Message from client {i}"
                
        finally:
            for client in clients:
                try:
                    await client.close()
                except:
                    pass

class TestConnectionLifecycle:
    
    @pytest.mark.asyncio
    async def test_connection_context_persistence(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            await websocket.recv()
            
            for i in range(3):
                msg = message_factory("chat", text=f"Message {i}", user_id=777)
                await websocket.send(json.dumps(msg))
                
                response = json.loads(await websocket.recv())
                assert response["type"] == "chat_response"
                assert response["echo"]["text"] == f"Message {i}"
    
    @pytest.mark.asyncio
    async def test_graceful_disconnection(self, test_server):
        uri, server_manager = test_server
        
        websocket = await websocket_client(uri)
        try:
            await websocket.recv()
            
            msg = message_factory("chat", text="Goodbye", user_id=888)
            await websocket.send(json.dumps(msg))
            await websocket.recv()
            
        finally:
            await websocket.close()

class TestErrorHandling:
    
    @pytest.mark.asyncio
    async def test_invalid_json_handling(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            await websocket.recv()
            
            try:
                await websocket.send("invalid json")
                
                try:
                    await asyncio.wait_for(websocket.recv(), timeout=1.0)
                except (websockets.exceptions.ConnectionClosed, asyncio.TimeoutError):
                    pass
                    
            except websockets.exceptions.ConnectionClosed:
                pass
    
    @pytest.mark.asyncio
    async def test_missing_message_type(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            await websocket.recv()
            
            try:
                await websocket.send(json.dumps({"data": "no type field"}))
                
                try:
                    await asyncio.wait_for(websocket.recv(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass
                    
            except websockets.exceptions.ConnectionClosed:
                pass
    
    @pytest.mark.asyncio
    async def test_unknown_message_type(self, test_server):
        uri, server_manager = test_server
        
        async with await websocket_client(uri) as websocket:
            await websocket.recv()
            
            unknown_msg = message_factory("unknown_type", data="test")
            await websocket.send(json.dumps(unknown_msg))
            
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"]) 