"""
Thread safety tests for WebSocket wrapper
"""

import asyncio
import pytest
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from aiows import WebSocket, ConnectionError


class TestWebSocketThreadSafety:
    """Test thread safety of WebSocket wrapper"""
    
    @pytest.fixture
    def mock_websocket(self):
        """Create mock websocket for testing"""
        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()
        mock_ws.recv = AsyncMock()
        mock_ws.close = AsyncMock()
        return mock_ws
    
    @pytest.fixture
    def websocket_wrapper(self, mock_websocket):
        """Create WebSocket wrapper with mock"""
        return WebSocket(mock_websocket, operation_timeout=1.0)
    
    @pytest.mark.asyncio
    async def test_concurrent_close_calls_no_exceptions(self, websocket_wrapper):
        """Test that concurrent close() calls don't cause exceptions"""
        
        async def close_task():
            """Task that calls close()"""
            try:
                await websocket_wrapper.close()
                return True
            except Exception as e:
                return f"Exception: {e}"
        
        # Launch multiple concurrent close() calls
        tasks = [close_task() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed without exceptions
        for result in results:
            assert result is True, f"close() call failed: {result}"
        
        # Verify websocket is marked as closed
        assert websocket_wrapper.closed is True
        assert websocket_wrapper.is_closed is True
    
    @pytest.mark.asyncio
    async def test_concurrent_send_operations(self, websocket_wrapper, mock_websocket):
        """Test concurrent send operations work correctly"""
        
        async def send_task(data):
            """Task that sends data"""
            try:
                await websocket_wrapper.send_json({"id": data, "message": f"test_{data}"})
                return f"sent_{data}"
            except Exception as e:
                return f"error_{data}: {e}"
        
        # Configure mock to simulate successful sends
        mock_websocket.send.return_value = None
        
        # Launch multiple concurrent send operations
        tasks = [send_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        # All sends should succeed
        success_count = sum(1 for r in results if r.startswith("sent_"))
        assert success_count == 10, f"Expected 10 successful sends, got {success_count}"
        
        # Verify all sends were called
        assert mock_websocket.send.call_count == 10
    
    @pytest.mark.asyncio
    async def test_concurrent_receive_operations(self, websocket_wrapper, mock_websocket):
        """Test concurrent receive operations work correctly"""
        
        # Configure mock to return different data for each call
        receive_data = [f'{{"id": {i}, "data": "test_{i}"}}' for i in range(5)]
        mock_websocket.recv.side_effect = receive_data
        
        async def receive_task(task_id):
            """Task that receives data"""
            try:
                data = await websocket_wrapper.receive_json()
                return f"received_{task_id}_{data['id']}"
            except Exception as e:
                return f"error_{task_id}: {e}"
        
        # Launch multiple concurrent receive operations
        tasks = [receive_task(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All receives should succeed
        success_count = sum(1 for r in results if r.startswith("received_"))
        assert success_count == 5, f"Expected 5 successful receives, got {success_count}"
        
        # Verify all receives were called
        assert mock_websocket.recv.call_count == 5
    
    @pytest.mark.asyncio
    async def test_mixed_concurrent_operations(self, websocket_wrapper, mock_websocket):
        """Test mixed send/receive/close operations concurrently"""
        
        # Configure mocks
        mock_websocket.send.return_value = None
        mock_websocket.recv.return_value = '{"test": "data"}'
        
        async def send_task():
            try:
                await websocket_wrapper.send_json({"type": "test"})
                return "send_ok"
            except Exception as e:
                return f"send_error: {e}"
        
        async def receive_task():
            try:
                await websocket_wrapper.receive_json()
                return "receive_ok"
            except Exception as e:
                return f"receive_error: {e}"
        
        async def close_task():
            try:
                await websocket_wrapper.close()
                return "close_ok"
            except Exception as e:
                return f"close_error: {e}"
        
        # Mix of operations
        tasks = [
            send_task(), send_task(),
            receive_task(), receive_task(),
            close_task()
        ]
        
        results = await asyncio.gather(*tasks)
        
        # At least the close operation should succeed
        close_results = [r for r in results if r.startswith("close")]
        assert len(close_results) == 1
        assert close_results[0] == "close_ok"
        
        # After close, websocket should be marked as closed
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_send(self, websocket_wrapper, mock_websocket):
        """Test timeout protection for send operations"""
        
        # Configure mock to hang
        async def hanging_send(*args, **kwargs):
            await asyncio.sleep(2.0)  # Longer than timeout (1.0s)
        
        mock_websocket.send.side_effect = hanging_send
        
        # Send should timeout
        with pytest.raises(ConnectionError, match="Send operation timed out"):
            await websocket_wrapper.send_json({"test": "data"})
        
        # Connection should be marked as closed after timeout
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_receive(self, websocket_wrapper, mock_websocket):
        """Test timeout protection for receive operations"""
        
        # Configure mock to hang
        async def hanging_recv(*args, **kwargs):
            await asyncio.sleep(2.0)  # Longer than timeout (1.0s)
        
        mock_websocket.recv.side_effect = hanging_recv
        
        # Receive should timeout
        with pytest.raises(ConnectionError, match="Receive operation timed out"):
            await websocket_wrapper.receive_json()
        
        # Connection should be marked as closed after timeout
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_close(self, websocket_wrapper, mock_websocket):
        """Test timeout protection for close operation"""
        
        # Configure mock to hang
        async def hanging_close(*args, **kwargs):
            await asyncio.sleep(2.0)  # Longer than timeout (1.0s)
        
        mock_websocket.close.side_effect = hanging_close
        
        # Close should complete without raising timeout exception
        # (it's handled internally and logged as warning)
        await websocket_wrapper.close()
        
        # Connection should still be marked as closed
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_state_consistency_after_errors(self, websocket_wrapper, mock_websocket):
        """Test state consistency is maintained after errors"""
        
        # Configure mock to raise exception
        mock_websocket.send.side_effect = Exception("Network error")
        
        # First operation should fail and mark as closed
        with pytest.raises(ConnectionError):
            await websocket_wrapper.send_json({"test": "data"})
        
        assert websocket_wrapper.closed is True
        
        # Subsequent operations should also fail immediately
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.send_json({"test": "data2"})
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.receive_json()
    
    @pytest.mark.asyncio
    async def test_operations_after_close(self, websocket_wrapper):
        """Test operations fail properly after close()"""
        
        # Close the connection
        await websocket_wrapper.close()
        assert websocket_wrapper.closed is True
        
        # All operations should fail
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.send_json({"test": "data"})
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.receive_json()
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.send("test")
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.recv()
    
    @pytest.mark.asyncio
    async def test_performance_no_significant_degradation(self, mock_websocket):
        """Test that thread safety doesn't significantly impact performance"""
        
        # Test with shorter timeout for performance test
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=5.0)
        
        # Configure mocks for fast responses
        mock_websocket.send.return_value = None
        mock_websocket.recv.return_value = '{"test": "data"}'
        
        # Measure time for sequential operations
        start_time = time.time()
        for _ in range(100):
            await websocket_wrapper.send_json({"test": "data"})
        sequential_time = time.time() - start_time
        
        # Reset mock call count
        mock_websocket.send.reset_mock()
        
        # Measure time for concurrent operations (batched)
        start_time = time.time()
        batch_size = 10
        for i in range(0, 100, batch_size):
            tasks = [
                websocket_wrapper.send_json({"test": f"data_{j}"}) 
                for j in range(i, min(i + batch_size, 100))
            ]
            await asyncio.gather(*tasks)
        concurrent_time = time.time() - start_time
        
        # Concurrent operations should not be significantly slower
        # Allow up to 2x slower due to lock overhead
        max_allowed_ratio = 2.0
        actual_ratio = concurrent_time / sequential_time if sequential_time > 0 else 1.0
        
        assert actual_ratio <= max_allowed_ratio, (
            f"Performance degradation too high: {actual_ratio:.2f}x slower "
            f"(max allowed: {max_allowed_ratio}x)"
        )
        
        # Verify all operations completed
        assert mock_websocket.send.call_count == 100
    
    @pytest.mark.asyncio
    async def test_custom_timeout_setting(self, mock_websocket):
        """Test custom timeout setting"""
        
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=0.5)
        
        # Verify initial timeout
        assert websocket_wrapper._operation_timeout == 0.5
        
        # Change timeout
        websocket_wrapper.set_operation_timeout(2.0)
        assert websocket_wrapper._operation_timeout == 2.0
        
        # Test invalid timeout
        with pytest.raises(ValueError, match="Timeout must be positive"):
            websocket_wrapper.set_operation_timeout(-1.0)
        
        with pytest.raises(ValueError, match="Timeout must be positive"):
            websocket_wrapper.set_operation_timeout(0.0)
    
    @pytest.mark.asyncio
    async def test_backward_compatibility_is_closed_property(self, websocket_wrapper):
        """Test backward compatibility of is_closed property"""
        
        # Initially not closed
        assert websocket_wrapper.is_closed is False
        assert websocket_wrapper.closed is False
        
        # After close
        await websocket_wrapper.close()
        assert websocket_wrapper.is_closed is True
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_json_serialization_with_datetime(self, websocket_wrapper, mock_websocket):
        """Test JSON serialization with datetime objects works thread-safely"""
        
        mock_websocket.send.return_value = None
        
        async def send_with_datetime(task_id):
            try:
                data = {
                    "id": task_id,
                    "timestamp": datetime.now(),
                    "message": f"test_{task_id}"
                }
                await websocket_wrapper.send_json(data)
                return f"success_{task_id}"
            except Exception as e:
                return f"error_{task_id}: {e}"
        
        # Test concurrent sends with datetime serialization
        tasks = [send_with_datetime(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All should succeed
        success_count = sum(1 for r in results if r.startswith("success_"))
        assert success_count == 5
        
        # Verify all sends called and contain ISO format timestamps
        assert mock_websocket.send.call_count == 5
        for call in mock_websocket.send.call_args_list:
            sent_data = call[0][0]  # First argument of send()
            parsed = json.loads(sent_data)
            
            # Should have serialized datetime as ISO string
            assert "timestamp" in parsed
            assert isinstance(parsed["timestamp"], str)
            # Basic ISO format check (contains T separator)
            assert "T" in parsed["timestamp"] 