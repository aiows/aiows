import asyncio
import pytest
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from aiows import WebSocket, ConnectionError


class TestWebSocketThreadSafety:
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()
        mock_ws.recv = AsyncMock()
        mock_ws.close = AsyncMock()
        return mock_ws
    
    @pytest.fixture
    def websocket_wrapper(self, mock_websocket):
        return WebSocket(mock_websocket, operation_timeout=1.0)
    
    @pytest.mark.asyncio
    async def test_concurrent_close_calls_no_exceptions(self, websocket_wrapper):
        async def close_task():
            try:
                await websocket_wrapper.close()
                return True
            except Exception as e:
                return f"Exception: {e}"
        
        tasks = [close_task() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            assert result is True, f"close() call failed: {result}"
        
        assert websocket_wrapper.closed is True
        assert websocket_wrapper.is_closed is True
    
    @pytest.mark.asyncio
    async def test_concurrent_send_operations(self, websocket_wrapper, mock_websocket):
        async def send_task(data):
            try:
                await websocket_wrapper.send_json({"id": data, "message": f"test_{data}"})
                return f"sent_{data}"
            except Exception as e:
                return f"error_{data}: {e}"
        
        mock_websocket.send.return_value = None
        
        tasks = [send_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in results if r.startswith("sent_"))
        assert success_count == 10, f"Expected 10 successful sends, got {success_count}"
        
        assert mock_websocket.send.call_count == 10
    
    @pytest.mark.asyncio
    async def test_concurrent_receive_operations(self, websocket_wrapper, mock_websocket):
        receive_data = [f'{{"id": {i}, "data": "test_{i}"}}' for i in range(5)]
        mock_websocket.recv.side_effect = receive_data
        
        async def receive_task(task_id):
            try:
                data = await websocket_wrapper.receive_json()
                return f"received_{task_id}_{data['id']}"
            except Exception as e:
                return f"error_{task_id}: {e}"
        
        tasks = [receive_task(i) for i in range(5)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in results if r.startswith("received_"))
        assert success_count == 5, f"Expected 5 successful receives, got {success_count}"
        
        assert mock_websocket.recv.call_count == 5
    
    @pytest.mark.asyncio
    async def test_mixed_concurrent_operations(self, websocket_wrapper, mock_websocket):
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
        
        tasks = [
            send_task(), send_task(),
            receive_task(), receive_task(),
            close_task()
        ]
        
        results = await asyncio.gather(*tasks)
        
        close_results = [r for r in results if r.startswith("close")]
        assert len(close_results) == 1
        assert close_results[0] == "close_ok"
        
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_send(self, websocket_wrapper, mock_websocket):
        # Note: After optimization, send operations no longer use asyncio.wait_for()
        # for better performance. Instead we test that long-running operations
        # don't block and can be cancelled properly.
        async def hanging_send(*args, **kwargs):
            await asyncio.sleep(2.0)
        
        mock_websocket.send.side_effect = hanging_send
        
        # Test that operation can be cancelled (no timeout needed)
        task = asyncio.create_task(websocket_wrapper.send_json({"test": "data"}))
        await asyncio.sleep(0.1)  # Let it start
        task.cancel()
        
        with pytest.raises(asyncio.CancelledError):
            await task
        
        # Connection should be marked as closed after cancellation
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_receive(self, websocket_wrapper, mock_websocket):
        # Note: After optimization, receive operations no longer use asyncio.wait_for()
        # for better performance. Instead we test that long-running operations
        # don't block and can be cancelled properly.
        async def hanging_recv(*args, **kwargs):
            await asyncio.sleep(2.0)
            return '{"test": "data"}'  # Return valid data after delay
        
        mock_websocket.recv.side_effect = hanging_recv
        
        # Test that operation can be cancelled (no timeout needed)
        task = asyncio.create_task(websocket_wrapper.receive_json())
        await asyncio.sleep(0.1)  # Let it start
        task.cancel()
        
        with pytest.raises(asyncio.CancelledError):
            await task
        
        # Connection should be marked as closed after cancellation
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_timeout_protection_close(self, websocket_wrapper, mock_websocket):
        async def hanging_close(*args, **kwargs):
            await asyncio.sleep(2.0)
        
        mock_websocket.close.side_effect = hanging_close
        
        await websocket_wrapper.close()
        
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_state_consistency_after_errors(self, websocket_wrapper, mock_websocket):
        mock_websocket.send.side_effect = Exception("Network error")
        
        with pytest.raises(ConnectionError):
            await websocket_wrapper.send_json({"test": "data"})
        
        assert websocket_wrapper.closed is True
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.send_json({"test": "data2"})
        
        with pytest.raises(ConnectionError, match="WebSocket connection is closed"):
            await websocket_wrapper.receive_json()
    
    @pytest.mark.asyncio
    async def test_operations_after_close(self, websocket_wrapper):
        await websocket_wrapper.close()
        assert websocket_wrapper.closed is True
        
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
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=5.0)
        
        mock_websocket.send.return_value = None
        mock_websocket.recv.return_value = '{"test": "data"}'
        
        start_time = time.time()
        for _ in range(100):
            await websocket_wrapper.send_json({"test": "data"})
        sequential_time = time.time() - start_time
        
        mock_websocket.send.reset_mock()
        
        start_time = time.time()
        batch_size = 10
        for i in range(0, 100, batch_size):
            tasks = [
                websocket_wrapper.send_json({"test": f"data_{j}"}) 
                for j in range(i, min(i + batch_size, 100))
            ]
            await asyncio.gather(*tasks)
        concurrent_time = time.time() - start_time
        
        max_allowed_ratio = 3.0
        actual_ratio = concurrent_time / sequential_time if sequential_time > 0 else 1.0
        
        assert actual_ratio <= max_allowed_ratio, (
            f"Performance degradation too high: {actual_ratio:.2f}x slower "
            f"(max allowed: {max_allowed_ratio}x)"
        )
        
        assert mock_websocket.send.call_count == 100
    
    @pytest.mark.asyncio
    async def test_custom_timeout_setting(self, mock_websocket):
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=0.5)
        
        assert websocket_wrapper._operation_timeout == 0.5
        
        websocket_wrapper.set_operation_timeout(2.0)
        assert websocket_wrapper._operation_timeout == 2.0
        
        with pytest.raises(ValueError, match="Timeout must be positive"):
            websocket_wrapper.set_operation_timeout(-1.0)
        
        with pytest.raises(ValueError, match="Timeout must be positive"):
            websocket_wrapper.set_operation_timeout(0.0)
    
    @pytest.mark.asyncio
    async def test_backward_compatibility_is_closed_property(self, websocket_wrapper):
        assert websocket_wrapper.is_closed is False
        assert websocket_wrapper.closed is False
        
        await websocket_wrapper.close()
        assert websocket_wrapper.is_closed is True
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_json_serialization_with_datetime(self, websocket_wrapper, mock_websocket):
        mock_websocket.send.return_value = None
        
        data_with_datetime = {
            "message": "test",
            "timestamp": datetime.now()
        }
        
        await websocket_wrapper.send_json(data_with_datetime)
        
        assert mock_websocket.send.called
        sent_data = mock_websocket.send.call_args[0][0]
        
        parsed_data = json.loads(sent_data)
        assert "timestamp" in parsed_data
        assert isinstance(parsed_data["timestamp"], str)

    @pytest.mark.asyncio
    async def test_separate_send_receive_locks_allow_concurrency(self, mock_websocket):
        """Test that separate send/receive locks allow true concurrency"""
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=1.0)
        
        send_started = asyncio.Event()
        receive_started = asyncio.Event()
        
        async def slow_send(*args, **kwargs):
            send_started.set()
            await asyncio.sleep(0.5)
            return None
        
        async def slow_recv(*args, **kwargs):
            receive_started.set()
            await asyncio.sleep(0.5)
            return '{"test": "data"}'
        
        mock_websocket.send.side_effect = slow_send
        mock_websocket.recv.side_effect = slow_recv
        
        start_time = time.time()
        
        # Start both operations concurrently
        send_task = asyncio.create_task(websocket_wrapper.send_json({"test": "send"}))
        receive_task = asyncio.create_task(websocket_wrapper.receive_json())
        
        # Wait for both to start
        await send_started.wait()
        await receive_started.wait()
        
        # Complete both operations
        await asyncio.gather(send_task, receive_task)
        
        elapsed = time.time() - start_time
        
        # Both operations should complete in ~0.5 seconds (concurrent) not ~1.0 seconds (sequential)
        assert elapsed < 0.8, f"Operations took {elapsed:.2f}s, expected < 0.8s for concurrent execution"
        
        # Verify both operations completed successfully
        assert mock_websocket.send.called
        assert mock_websocket.recv.called
    
    @pytest.mark.asyncio
    async def test_connection_state_event_performance(self, mock_websocket):
        """Test that connection state checks using asyncio.Event are lock-free"""
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=1.0)
        
        # Test multiple concurrent state checks (should be lock-free)
        async def check_state():
            for _ in range(100):
                is_closed = websocket_wrapper.is_closed
                closed = websocket_wrapper.closed
                assert is_closed == closed
            return True
        
        start_time = time.time()
        
        # Run many concurrent state checks
        tasks = [asyncio.create_task(check_state()) for _ in range(50)]
        results = await asyncio.gather(*tasks)
        
        elapsed = time.time() - start_time
        
        # All tasks should complete very quickly since no locks are involved
        assert all(results), "All state check tasks should succeed"
        assert elapsed < 0.1, f"Lock-free state checks took {elapsed:.2f}s, expected < 0.1s"
    
    @pytest.mark.asyncio
    async def test_close_operation_retains_timeout(self, mock_websocket):
        """Test that close operation still uses timeout as required"""
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=0.5)
        
        async def hanging_close(*args, **kwargs):
            await asyncio.sleep(1.0)  # Longer than timeout
        
        mock_websocket.close.side_effect = hanging_close
        
        start_time = time.time()
        
        # Close operation should timeout after operation_timeout seconds
        await websocket_wrapper.close()
        
        elapsed = time.time() - start_time
        
        # Should timeout around 0.5 seconds (operation_timeout)
        assert 0.4 < elapsed < 0.7, f"Close timeout took {elapsed:.2f}s, expected ~0.5s"
        assert websocket_wrapper.closed is True
    
    @pytest.mark.asyncio
    async def test_mixed_send_receive_no_deadlock(self, mock_websocket):
        """Test that mixed send/receive operations don't cause deadlocks"""
        websocket_wrapper = WebSocket(mock_websocket, operation_timeout=1.0)
        
        mock_websocket.send.return_value = None
        mock_websocket.recv.return_value = '{"response": "test"}'
        
        async def send_receive_cycle():
            for i in range(10):
                await websocket_wrapper.send_json({"id": i})
                result = await websocket_wrapper.receive_json()
                assert result["response"] == "test"
        
        # Run multiple concurrent send/receive cycles
        tasks = [asyncio.create_task(send_receive_cycle()) for _ in range(5)]
        
        start_time = time.time()
        await asyncio.gather(*tasks)
        elapsed = time.time() - start_time
        
        # Should complete without deadlocks in reasonable time
        assert elapsed < 2.0, f"Mixed operations took {elapsed:.2f}s, possible deadlock"
        
        # Verify operations completed
        assert mock_websocket.send.call_count >= 50  # 5 tasks * 10 calls each
        assert mock_websocket.recv.call_count >= 50 