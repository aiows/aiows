import pytest
from datetime import datetime
from unittest.mock import MagicMock

from aiows import (
    BaseMessage, 
    ChatMessage, 
    JoinRoomMessage, 
    GameActionMessage,
    Router,
    WebSocketServer,
    MessageValidationError
)
from aiows.dispatcher import MessageDispatcher


class TestBaseMessage:
    
    def test_base_message_creation(self):
        message = BaseMessage(type="test")
        
        assert message.type == "test"
        assert isinstance(message.timestamp, datetime)
    
    def test_chat_message_creation(self):
        message = ChatMessage(text="Hello", user_id=123)
        
        assert message.type == "chat"
        assert message.text == "Hello"
        assert message.user_id == 123
        assert isinstance(message.timestamp, datetime)
    
    def test_join_room_message_creation(self):
        message = JoinRoomMessage(room_id="room1", user_name="Alice")
        
        assert message.type == "join_room"
        assert message.room_id == "room1"
        assert message.user_name == "Alice"
    
    def test_game_action_message_creation(self):
        message = GameActionMessage(action="move", coordinates=(10, 20))
        
        assert message.type == "game_action"
        assert message.action == "move"
        assert message.coordinates == (10, 20)
    
    def test_message_dict_serialization(self):
        message = ChatMessage(text="Test", user_id=456)
        data = message.dict()
        
        assert data["type"] == "chat"
        assert data["text"] == "Test"
        assert data["user_id"] == 456
        assert "timestamp" in data


class TestRouter:
    
    def test_router_creation(self):
        router = Router()
        
        assert len(router._connect_handlers) == 0
        assert len(router._disconnect_handlers) == 0
        assert len(router._message_handlers) == 0
        assert len(router._sub_routers) == 0
    
    def test_connect_decorator(self):
        router = Router()
        
        @router.connect()
        async def test_handler(websocket):
            pass
        
        assert len(router._connect_handlers) == 1
        assert router._connect_handlers[0] == test_handler
    
    def test_disconnect_decorator(self):
        router = Router()
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            pass
        
        assert len(router._disconnect_handlers) == 1
        assert router._disconnect_handlers[0] == test_handler
    
    def test_message_decorator(self):
        router = Router()
        
        @router.message("chat")
        async def test_handler(websocket, message):
            pass
        
        assert len(router._message_handlers) == 1
        handler_info = router._message_handlers[0]
        assert handler_info["handler"] == test_handler
        assert handler_info["message_type"] == "chat"
    
    def test_message_decorator_without_type(self):
        router = Router()
        
        @router.message()
        async def test_handler(websocket, message):
            pass
        
        handler_info = router._message_handlers[0]
        assert handler_info["message_type"] is None
    
    def test_include_router(self):
        main_router = Router()
        sub_router = Router()
        
        main_router.include_router(sub_router, prefix="api")
        
        assert len(main_router._sub_routers) == 1
        sub_router_info = main_router._sub_routers[0]
        assert sub_router_info["router"] == sub_router
        assert sub_router_info["prefix"] == "api"


class TestWebSocketServer:
    
    def test_server_creation(self):
        server = WebSocketServer()
        
        assert server.host == "localhost"
        assert server.port == 8000
        assert isinstance(server.router, Router)
        assert isinstance(server.dispatcher, MessageDispatcher)
        assert len(server._connections) == 0
    
    def test_include_router(self):
        server = WebSocketServer()
        router = Router()
        
        @router.connect()
        async def test_handler(websocket):
            pass
        
        server.include_router(router)
        
        assert server.router == router
        assert len(server.dispatcher.router._connect_handlers) == 1


class TestMessageDispatcher:
    
    def test_dispatcher_creation(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        assert dispatcher.router == router
    
    @pytest.mark.asyncio
    async def test_dispatch_connect(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        handler_called = False
        
        @router.connect()
        async def test_handler(websocket):
            nonlocal handler_called
            handler_called = True
        
        mock_websocket = MagicMock()
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_dispatch_disconnect(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        received_reason = None
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            nonlocal received_reason
            received_reason = reason
        
        mock_websocket = MagicMock()
        
        await dispatcher.dispatch_disconnect(mock_websocket, "test reason")
        
        assert received_reason == "test reason"
    
    @pytest.mark.asyncio
    async def test_dispatch_message_valid(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        received_message = None
        
        @router.message("test")
        async def test_handler(websocket, message):
            nonlocal received_message
            received_message = message
        
        mock_websocket = MagicMock()
        
        message_data = {"type": "test", "timestamp": datetime.now().isoformat()}
        
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert received_message is not None
        assert received_message.type == "test"
    
    @pytest.mark.asyncio
    async def test_dispatch_message_invalid(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        mock_websocket = MagicMock()
        
        message_data = {"invalid": "data"}
        
        with pytest.raises(MessageValidationError):
            await dispatcher.dispatch_message(mock_websocket, message_data) 


class TestFiltersModule:
    
    def test_filters_import_without_error(self):
        try:
            import aiows.filters
            assert aiows.filters is not None
        except ImportError as e:
            pytest.fail(f"Failed to import aiows.filters: {e}")
    
    def test_filters_module_has_docstring(self):
        import aiows.filters
        
        assert aiows.filters.__doc__ is not None
        assert len(aiows.filters.__doc__.strip()) > 0
        
        docstring = aiows.filters.__doc__.lower()
        assert "todo" in docstring or "placeholder" in docstring
    
    def test_filters_module_is_empty_placeholder(self):
        import aiows.filters
        
        public_attrs = [attr for attr in dir(aiows.filters) if not attr.startswith('_')]
        
        expected_attrs = []
        assert public_attrs == expected_attrs, f"Expected empty placeholder, but found: {public_attrs}" 