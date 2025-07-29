import pytest
import json
from unittest.mock import AsyncMock
import logging

from aiows.websocket import WebSocket
from aiows.exceptions import MessageSizeError, ConnectionError


@pytest.mark.asyncio
class TestMessageSizeLimits:

    @pytest.fixture
    def mock_websocket(self):
        websocket = AsyncMock()
        return websocket

    @pytest.fixture
    def small_limit_ws(self, mock_websocket):
        return WebSocket(mock_websocket, max_message_size=100)

    @pytest.fixture
    def default_ws(self, mock_websocket):
        return WebSocket(mock_websocket)

    def test_init_with_valid_max_message_size(self, mock_websocket):
        ws = WebSocket(mock_websocket, max_message_size=1000)
        assert ws._max_message_size == 1000

    def test_init_with_invalid_max_message_size(self, mock_websocket):
        with pytest.raises(ValueError, match="max_message_size must be positive"):
            WebSocket(mock_websocket, max_message_size=0)
        
        with pytest.raises(ValueError, match="max_message_size must be positive"):
            WebSocket(mock_websocket, max_message_size=-1)

    @pytest.mark.asyncio
    async def test_recv_normal_message(self, small_limit_ws):
        small_message = "Hello world!"
        small_limit_ws._websocket.recv.return_value = small_message
        
        result = await small_limit_ws.recv()
        assert result == small_message

    @pytest.mark.asyncio
    async def test_recv_oversized_message(self, small_limit_ws):
        oversized_message = "x" * 200
        small_limit_ws._websocket.recv.return_value = oversized_message
        
        with pytest.raises(MessageSizeError) as exc_info:
            await small_limit_ws.recv()
        
        assert "Message size 200 exceeds limit 100" in str(exc_info.value)
        assert not small_limit_ws.is_closed

    @pytest.mark.asyncio
    async def test_receive_json_normal_message(self, small_limit_ws):
        small_json = json.dumps({"message": "hello"})
        small_limit_ws._websocket.recv.return_value = small_json
        
        result = await small_limit_ws.receive_json()
        assert result == {"message": "hello"}

    @pytest.mark.asyncio
    async def test_receive_json_oversized_message(self, small_limit_ws):
        oversized_json = json.dumps({"data": "x" * 200})
        small_limit_ws._websocket.recv.return_value = oversized_json
        
        with pytest.raises(MessageSizeError) as exc_info:
            await small_limit_ws.receive_json()
        
        assert "exceeds limit 100" in str(exc_info.value)
        assert not small_limit_ws.is_closed

    @pytest.mark.asyncio
    async def test_json_bomb_protection(self, small_limit_ws):
        json_bomb = json.dumps({"key" + str(i): "value" * 10 for i in range(50)})
        small_limit_ws._websocket.recv.return_value = json_bomb
        
        with pytest.raises(MessageSizeError):
            await small_limit_ws.receive_json()

    @pytest.mark.asyncio
    async def test_size_check_before_json_parsing(self, small_limit_ws):
        malformed_oversized_json = '{"key": "value"' + "x" * 200
        small_limit_ws._websocket.recv.return_value = malformed_oversized_json
        
        with pytest.raises(MessageSizeError):
            await small_limit_ws.receive_json()

    @pytest.mark.asyncio
    async def test_default_message_size_limit(self, default_ws):
        assert default_ws._max_message_size == 1024 * 1024

    @pytest.mark.asyncio
    async def test_large_but_acceptable_message(self, default_ws):
        large_message = "x" * (512 * 1024)
        default_ws._websocket.recv.return_value = large_message
        
        result = await default_ws.recv()
        assert result == large_message

    @pytest.mark.asyncio
    async def test_exact_limit_message(self, small_limit_ws):
        exact_limit_message = "x" * 100
        small_limit_ws._websocket.recv.return_value = exact_limit_message
        
        result = await small_limit_ws.recv()
        assert result == exact_limit_message

    @pytest.mark.asyncio
    async def test_one_byte_over_limit(self, small_limit_ws):
        over_limit_message = "x" * 101
        small_limit_ws._websocket.recv.return_value = over_limit_message
        
        with pytest.raises(MessageSizeError):
            await small_limit_ws.recv()

    @pytest.mark.asyncio
    async def test_connection_stays_open_after_size_error(self, small_limit_ws):
        oversized_message = "x" * 200
        small_limit_ws._websocket.recv.return_value = oversized_message
        
        with pytest.raises(MessageSizeError):
            await small_limit_ws.recv()
        
        assert not small_limit_ws.is_closed
        
        normal_message = "Hello"
        small_limit_ws._websocket.recv.return_value = normal_message
        
        result = await small_limit_ws.recv()
        assert result == normal_message

    @pytest.mark.asyncio
    async def test_logging_of_blocked_messages(self, small_limit_ws, caplog):
        with caplog.at_level(logging.WARNING):
            oversized_message = "x" * 200
            small_limit_ws._websocket.recv.return_value = oversized_message
            
            with pytest.raises(MessageSizeError):
                await small_limit_ws.recv()
            
            assert "Oversized message blocked: 200 bytes (limit: 100)" in caplog.text

    @pytest.mark.asyncio
    async def test_performance_impact_minimal(self, default_ws):
        import time
        
        normal_message = "Hello world!"
        default_ws._websocket.recv.return_value = normal_message
        
        start_time = time.time()
        for _ in range(100):
            result = await default_ws.recv()
            assert result == normal_message
        end_time = time.time()
        
        elapsed = end_time - start_time
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_unicode_message_size_handling(self, small_limit_ws):
        unicode_message = "привет" * 20
        small_limit_ws._websocket.recv.return_value = unicode_message
        
        if len(unicode_message.encode('utf-8')) > 100:
            with pytest.raises(MessageSizeError):
                await small_limit_ws.recv()
        else:
            result = await small_limit_ws.recv()
            assert result == unicode_message

    @pytest.mark.asyncio
    async def test_empty_message(self, small_limit_ws):
        empty_message = ""
        small_limit_ws._websocket.recv.return_value = empty_message
        
        result = await small_limit_ws.recv()
        assert result == empty_message

    @pytest.mark.asyncio
    async def test_network_error_vs_size_error(self, small_limit_ws):
        small_limit_ws._websocket.recv.side_effect = Exception("Network error")
        
        with pytest.raises(ConnectionError):
            await small_limit_ws.recv()
        
        assert small_limit_ws.is_closed 