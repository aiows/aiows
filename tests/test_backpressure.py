"""
Tests for backpressure handling functionality
"""

import pytest
import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

from aiows import WebSocket, WebSocketServer
from aiows.websocket import BackpressureManager, BackpressureMetrics, SendQueueItem, backpressure_metrics
from aiows.settings import create_settings


class TestBackpressureMetrics:
    """Test backpressure metrics collection"""
    
    def test_initialization(self):
        metrics = BackpressureMetrics()
        
        assert metrics.messages_queued == 0
        assert metrics.messages_sent == 0
        assert metrics.messages_dropped == 0
        assert metrics.queue_overflow_events == 0
        assert metrics.slow_client_disconnections == 0
        assert len(metrics.connection_metrics) == 0
    
    def test_record_message_queued(self):
        metrics = BackpressureMetrics()
        connection_id = "test_conn"
        
        metrics.record_message_queued(connection_id, 5)
        
        assert metrics.messages_queued == 1
        assert connection_id in metrics.connection_metrics
        assert metrics.connection_metrics[connection_id]['messages_queued'] == 1
        assert metrics.connection_metrics[connection_id]['current_queue_size'] == 5
    
    def test_record_message_sent(self):
        metrics = BackpressureMetrics()
        connection_id = "test_conn"
        
        metrics.record_message_sent(connection_id, 100.5, 3)
        
        assert metrics.messages_sent == 1
        assert metrics.total_send_time_ms == 100.5
        assert metrics.connection_metrics[connection_id]['messages_sent'] == 1
        assert metrics.connection_metrics[connection_id]['total_send_time_ms'] == 100.5
    
    def test_record_message_dropped(self):
        metrics = BackpressureMetrics()
        connection_id = "test_conn"
        
        metrics.record_message_dropped(connection_id, "queue_overflow")
        
        assert metrics.messages_dropped == 1
        assert metrics.connection_metrics[connection_id]['messages_dropped'] == 1
        assert metrics.connection_metrics[connection_id]['last_drop_reason'] == "queue_overflow"
    
    def test_get_global_stats(self):
        metrics = BackpressureMetrics()
        
        metrics.record_message_queued("conn1", 1)
        metrics.record_message_sent("conn1", 50.0, 0)
        
        stats = metrics.get_global_stats()
        
        assert 'uptime_seconds' in stats
        assert stats['messages_queued'] == 1
        assert stats['messages_sent'] == 1
        assert stats['average_send_time_ms'] == 50.0
        assert stats['active_connections'] == 1


class TestSendQueueItem:
    """Test send queue item"""
    
    def test_initialization(self):
        data = '{"test": "data"}'
        created_at = time.time()
        
        item = SendQueueItem(data, created_at, "json")
        
        assert item.data == data
        assert item.created_at == created_at
        assert item.item_type == "json"
    
    def test_default_item_type(self):
        item = SendQueueItem("test", time.time())
        assert item.item_type == "data"


class TestBackpressureManager:
    """Test backpressure manager"""
    
    def test_initialization(self):
        manager = BackpressureManager(
            connection_id="test_conn",
            max_queue_size=50,
            overflow_strategy="drop_oldest"
        )
        
        assert manager.connection_id == "test_conn"
        assert manager.max_queue_size == 50
        assert manager.overflow_strategy == "drop_oldest"
        assert manager.queue_size == 0
        assert not manager.is_queue_full
        assert not manager.is_slow_client
    
    def test_queue_properties(self):
        manager = BackpressureManager("test", max_queue_size=10, slow_client_threshold=80)
        
        for i in range(8):
            asyncio.run(manager.enqueue_message(f"msg{i}"))
        
        assert manager.queue_size == 8
        assert manager.queue_utilization_percent == 80.0
        assert manager.is_slow_client
        assert not manager.is_queue_full
    
    @pytest.mark.asyncio
    async def test_enqueue_message_success(self):
        manager = BackpressureManager("test", max_queue_size=5)
        
        success = await manager.enqueue_message("test_data", "data")
        
        assert success is True
        assert manager.queue_size == 1
    
    @pytest.mark.asyncio
    async def test_enqueue_message_overflow_drop_oldest(self):
        manager = BackpressureManager("test", max_queue_size=2, overflow_strategy="drop_oldest")
        
        await manager.enqueue_message("msg1")
        await manager.enqueue_message("msg2")
        
        success = await manager.enqueue_message("msg3")
        
        assert success is True
        assert manager.queue_size == 2
        
        item = await manager.dequeue_message()
        assert "msg2" in item.data
    
    @pytest.mark.asyncio
    async def test_enqueue_message_overflow_drop_newest(self):
        manager = BackpressureManager("test", max_queue_size=2, overflow_strategy="drop_newest")
        
        await manager.enqueue_message("msg1")
        await manager.enqueue_message("msg2")
        
        success = await manager.enqueue_message("msg3")
        
        assert success is False
        assert manager.queue_size == 2
    
    @pytest.mark.asyncio
    async def test_enqueue_message_overflow_reject(self):
        manager = BackpressureManager("test", max_queue_size=2, overflow_strategy="reject")
        
        await manager.enqueue_message("msg1")
        await manager.enqueue_message("msg2")
        
        success = await manager.enqueue_message("msg3")
        
        assert success is False
        assert manager.queue_size == 2
    
    @pytest.mark.asyncio
    async def test_dequeue_message(self):
        manager = BackpressureManager("test")
        
        await manager.enqueue_message("test_data", "data")
        item = await manager.dequeue_message()
        
        assert item is not None
        assert item.data == "test_data"
        assert item.item_type == "data"
        assert manager.queue_size == 0
    
    @pytest.mark.asyncio
    async def test_dequeue_empty_queue(self):
        manager = BackpressureManager("test")
        
        item = await manager.dequeue_message()
        
        assert item is None
    
    def test_slow_client_detection(self):
        manager = BackpressureManager("test", max_queue_size=10, 
                                    slow_client_threshold=50, slow_client_timeout=1.0)
        
        for i in range(4):
            asyncio.run(manager.enqueue_message(f"msg{i}"))
        
        assert not manager.is_slow_client
        assert manager.slow_client_detected_at is None
        
        asyncio.run(manager.enqueue_message("msg_trigger"))
        
        assert manager.is_slow_client
        assert manager.slow_client_detected_at is not None
        
        assert not manager.should_disconnect_slow_client
        
        manager.slow_client_detected_at = time.time() - 2.0
        assert manager.should_disconnect_slow_client
    
    def test_record_successful_send(self):
        manager = BackpressureManager("test", enable_metrics=True)
        
        manager.record_successful_send(150.5)
        
        assert manager.last_successful_send > 0
    
    def test_get_health_stats(self):
        manager = BackpressureManager("test")
        
        stats = manager.get_health_stats()
        
        assert 'connection_id' in stats
        assert 'queue_size' in stats
        assert 'queue_utilization_percent' in stats
        assert 'is_slow_client' in stats
        assert 'time_since_last_send_seconds' in stats


class TestWebSocketBackpressure:
    """Test WebSocket class with backpressure enabled"""
    
    @pytest.fixture
    def mock_websocket(self):
        mock = AsyncMock()
        mock.send = AsyncMock()
        mock.recv = AsyncMock()
        mock.close = AsyncMock()
        return mock
    
    @pytest.fixture
    def backpressure_settings(self):
        return {
            'enabled': True,
            'send_queue_max_size': 10,
            'send_queue_overflow_strategy': 'drop_oldest',
            'slow_client_threshold': 80,
            'slow_client_timeout': 5.0,
            'max_response_time_ms': 1000,
            'enable_send_metrics': True
        }
    
    @pytest.fixture
    def websocket_with_backpressure(self, mock_websocket, backpressure_settings):
        return WebSocket(mock_websocket, backpressure_settings=backpressure_settings)
    
    def test_initialization_with_backpressure(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        
        assert ws.backpressure_enabled is True
        assert ws._backpressure_manager is not None
    
    def test_initialization_without_backpressure(self, mock_websocket):
        ws = WebSocket(mock_websocket)
        
        assert ws.backpressure_enabled is False
        assert ws._backpressure_manager is None
        assert ws._send_task is None
    
    @pytest.mark.asyncio
    async def test_send_json_with_backpressure(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        test_data = {"type": "test", "message": "hello"}
        
        await ws.send_json(test_data)
        
        assert ws.send_queue_size == 1
        
        await asyncio.sleep(0.1)
        
        ws._websocket.send.assert_called()
    
    @pytest.mark.asyncio
    async def test_send_with_backpressure(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        test_data = "test message"
        
        await ws.send(test_data)
        
        assert ws.send_queue_size == 1
        
        await asyncio.sleep(0.1)
        
        ws._websocket.send.assert_called_with(test_data)
    
    @pytest.mark.asyncio
    async def test_send_without_backpressure(self, mock_websocket):
        ws = WebSocket(mock_websocket)
        test_data = "test message"
        
        await ws.send(test_data)
        
        assert ws.send_queue_size == 0
        mock_websocket.send.assert_called_once_with(test_data)
    
    @pytest.mark.asyncio
    async def test_queue_overflow_handling(self, mock_websocket, backpressure_settings):
        backpressure_settings['send_queue_max_size'] = 2
        ws = WebSocket(mock_websocket, backpressure_settings=backpressure_settings)
        
        ws._websocket.send = AsyncMock(side_effect=asyncio.sleep(10))
        
        await ws.send("msg1")
        await ws.send("msg2")
        await ws.send("msg3")
        
        assert ws.send_queue_size == 2
    
    @pytest.mark.asyncio
    async def test_backpressure_stats(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        
        stats = ws.get_backpressure_stats()
        
        assert stats['backpressure_enabled'] is True
        assert stats['connection_id'] == ws.connection_id
        assert 'queue_size' in stats
        assert 'queue_utilization_percent' in stats
    
    @pytest.mark.asyncio
    async def test_enable_backpressure_runtime(self, mock_websocket, backpressure_settings):
        ws = WebSocket(mock_websocket)
        
        assert ws.backpressure_enabled is False
        
        ws.enable_backpressure(backpressure_settings)
        
        assert ws.backpressure_enabled is True
        assert ws._backpressure_manager is not None
    
    @pytest.mark.asyncio
    async def test_disable_backpressure(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        
        assert ws.backpressure_enabled is True
        
        ws.disable_backpressure()
        
        assert ws.backpressure_enabled is False
        assert ws._backpressure_manager is None
    
    @pytest.mark.asyncio
    async def test_slow_client_detection_and_disconnect(self, mock_websocket):
        backpressure_settings = {
            'enabled': True,
            'send_queue_max_size': 5,
            'slow_client_threshold': 60,
            'slow_client_timeout': 0.1,
            'enable_send_metrics': True
        }
        
        ws = WebSocket(mock_websocket, backpressure_settings=backpressure_settings)
        
        ws._websocket.send = AsyncMock(side_effect=asyncio.sleep(10))
        
        for i in range(4):
            await ws.send(f"msg{i}")
        
        await asyncio.sleep(0.2)
        
        assert ws.is_closed
    
    @pytest.mark.asyncio
    async def test_cleanup_on_close(self, websocket_with_backpressure):
        ws = websocket_with_backpressure
        
        await ws.send("test_message")
        
        assert ws._send_task is not None
        
        await ws.close()
        
        await asyncio.sleep(0.1)
        
        assert ws._send_task.cancelled() or ws._send_task.done()


class TestWebSocketServerBackpressure:
    """Test WebSocketServer with backpressure integration"""
    
    @pytest.fixture
    def server_with_backpressure(self):
        settings = create_settings("testing")
        settings.backpressure.enabled = True
        settings.backpressure.send_queue_max_size = 5
        
        return WebSocketServer.from_settings(settings)
    
    def test_backpressure_stats_empty(self, server_with_backpressure):
        server = server_with_backpressure
        
        stats = server.get_backpressure_stats()
        
        assert 'global_stats' in stats
        assert 'connection_stats' in stats
        assert len(stats['connection_stats']) == 0
    
    def test_get_slow_connections_empty(self, server_with_backpressure):
        server = server_with_backpressure
        
        slow_connections = server.get_slow_connections()
        
        assert len(slow_connections) == 0


class TestBackpressureIntegration:
    """Integration tests for backpressure functionality"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_backpressure_flow(self):
        """Test complete backpressure flow from server to WebSocket"""
        settings = create_settings("testing")
        settings.backpressure.enabled = True
        settings.backpressure.send_queue_max_size = 3
        settings.backpressure.slow_client_threshold = 66
        
        server = WebSocketServer.from_settings(settings)
        
        mock_websocket = AsyncMock()
        mock_websocket.send = AsyncMock()
        
        backpressure_settings = {
            'enabled': settings.backpressure.enabled,
            'send_queue_max_size': settings.backpressure.send_queue_max_size,
            'send_queue_overflow_strategy': settings.backpressure.send_queue_overflow_strategy,
            'slow_client_threshold': settings.backpressure.slow_client_threshold,
            'slow_client_timeout': settings.backpressure.slow_client_timeout,
            'max_response_time_ms': settings.backpressure.max_response_time_ms,
            'enable_send_metrics': settings.backpressure.enable_send_metrics
        }
        
        ws = WebSocket(mock_websocket, backpressure_settings=backpressure_settings)
        
        await ws.send_json({"test": "message1"})
        await ws.send_json({"test": "message2"})
        
        assert ws.send_queue_size == 2
        assert abs(ws.send_queue_utilization_percent - 66.67) < 0.01
        
        stats = ws.get_backpressure_stats()
        assert stats['is_slow_client'] is True
        
        await ws.close()
    
    @pytest.mark.asyncio 
    async def test_backward_compatibility(self):
        """Test that existing code works without backpressure"""
        mock_websocket = AsyncMock()
        mock_websocket.send = AsyncMock()
        
        ws = WebSocket(mock_websocket)
        
        await ws.send_json({"test": "data"})
        await ws.send("test string")
        
        assert ws.send_queue_size == 0
        assert mock_websocket.send.call_count == 2
        
        assert ws.backpressure_enabled is False
        stats = ws.get_backpressure_stats()
        assert stats['backpressure_enabled'] is False 