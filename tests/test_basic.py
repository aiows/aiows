"""
Basic tests for aiows MVP functionality
"""

import pytest
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

from aiows import (
    BaseMessage, 
    ChatMessage, 
    JoinRoomMessage, 
    GameActionMessage,
    Router,
    WebSocketServer,
    WebSocket,
    AiowsException,
    ConnectionError,
    MessageValidationError
)
from aiows.dispatcher import MessageDispatcher


class TestBaseMessage:
    """Test BaseMessage and its subclasses"""
    
    def test_base_message_creation(self):
        """Test BaseMessage can be created with required fields"""
        message = BaseMessage(type="test")
        
        assert message.type == "test"
        assert isinstance(message.timestamp, datetime)
    
    def test_chat_message_creation(self):
        """Test ChatMessage creation and validation"""
        message = ChatMessage(text="Hello", user_id=123)
        
        assert message.type == "chat"
        assert message.text == "Hello"
        assert message.user_id == 123
        assert isinstance(message.timestamp, datetime)
    
    def test_join_room_message_creation(self):
        """Test JoinRoomMessage creation and validation"""
        message = JoinRoomMessage(room_id="room1", user_name="Alice")
        
        assert message.type == "join_room"
        assert message.room_id == "room1"
        assert message.user_name == "Alice"
    
    def test_game_action_message_creation(self):
        """Test GameActionMessage creation and validation"""
        message = GameActionMessage(action="move", coordinates=(10, 20))
        
        assert message.type == "game_action"
        assert message.action == "move"
        assert message.coordinates == (10, 20)
    
    def test_message_dict_serialization(self):
        """Test message serialization to dictionary"""
        message = ChatMessage(text="Test", user_id=456)
        data = message.dict()
        
        assert data["type"] == "chat"
        assert data["text"] == "Test"
        assert data["user_id"] == 456
        assert "timestamp" in data


class TestRouter:
    """Test Router functionality"""
    
    def test_router_creation(self):
        """Test Router can be created"""
        router = Router()
        
        assert len(router._connect_handlers) == 0
        assert len(router._disconnect_handlers) == 0
        assert len(router._message_handlers) == 0
        assert len(router._sub_routers) == 0
    
    def test_connect_decorator(self):
        """Test connect decorator registers handler"""
        router = Router()
        
        @router.connect()
        async def test_handler(websocket):
            pass
        
        assert len(router._connect_handlers) == 1
        assert router._connect_handlers[0] == test_handler
    
    def test_disconnect_decorator(self):
        """Test disconnect decorator registers handler"""
        router = Router()
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            pass
        
        assert len(router._disconnect_handlers) == 1
        assert router._disconnect_handlers[0] == test_handler
    
    def test_message_decorator(self):
        """Test message decorator registers handler"""
        router = Router()
        
        @router.message("chat")
        async def test_handler(websocket, message):
            pass
        
        assert len(router._message_handlers) == 1
        handler_info = router._message_handlers[0]
        assert handler_info["handler"] == test_handler
        assert handler_info["message_type"] == "chat"
    
    def test_message_decorator_without_type(self):
        """Test message decorator without message type"""
        router = Router()
        
        @router.message()
        async def test_handler(websocket, message):
            pass
        
        handler_info = router._message_handlers[0]
        assert handler_info["message_type"] is None
    
    def test_include_router(self):
        """Test including sub-router"""
        main_router = Router()
        sub_router = Router()
        
        main_router.include_router(sub_router, prefix="api")
        
        assert len(main_router._sub_routers) == 1
        sub_router_info = main_router._sub_routers[0]
        assert sub_router_info["router"] == sub_router
        assert sub_router_info["prefix"] == "api"


class TestWebSocketServer:
    """Test WebSocketServer functionality"""
    
    def test_server_creation(self):
        """Test WebSocketServer can be created"""
        server = WebSocketServer()
        
        assert server.host == "localhost"
        assert server.port == 8000
        assert isinstance(server.router, Router)
        assert isinstance(server.dispatcher, MessageDispatcher)
        assert len(server._connections) == 0
    
    def test_include_router(self):
        """Test including router to server"""
        server = WebSocketServer()
        router = Router()
        
        # Add a handler to router to verify it's included
        @router.connect()
        async def test_handler(websocket):
            pass
        
        server.include_router(router)
        
        assert server.router == router
        assert len(server.dispatcher.router._connect_handlers) == 1


class TestMessageDispatcher:
    """Test MessageDispatcher functionality"""
    
    def test_dispatcher_creation(self):
        """Test MessageDispatcher can be created"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        assert dispatcher.router == router
    
    @pytest.mark.asyncio
    async def test_dispatch_connect(self):
        """Test dispatching connect event"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        # Mock handler
        handler_called = False
        
        @router.connect()
        async def test_handler(websocket):
            nonlocal handler_called
            handler_called = True
        
        # Mock websocket
        mock_websocket = MagicMock()
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert handler_called
    
    @pytest.mark.asyncio
    async def test_dispatch_disconnect(self):
        """Test dispatching disconnect event"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        # Mock handler
        received_reason = None
        
        @router.disconnect()
        async def test_handler(websocket, reason):
            nonlocal received_reason
            received_reason = reason
        
        # Mock websocket
        mock_websocket = MagicMock()
        
        await dispatcher.dispatch_disconnect(mock_websocket, "test reason")
        
        assert received_reason == "test reason"
    
    @pytest.mark.asyncio
    async def test_dispatch_message_valid(self):
        """Test dispatching valid message"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        # Mock handler
        received_message = None
        
        @router.message("test")
        async def test_handler(websocket, message):
            nonlocal received_message
            received_message = message
        
        # Mock websocket
        mock_websocket = MagicMock()
        
        # Valid message data
        message_data = {"type": "test", "timestamp": datetime.now().isoformat()}
        
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert received_message is not None
        assert received_message.type == "test"
    
    @pytest.mark.asyncio
    async def test_dispatch_message_invalid(self):
        """Test dispatching invalid message raises exception"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        # Mock websocket
        mock_websocket = MagicMock()
        
        # Invalid message data (missing required field)
        message_data = {"invalid": "data"}
        
        with pytest.raises(MessageValidationError):
            await dispatcher.dispatch_message(mock_websocket, message_data) 