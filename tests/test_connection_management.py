import asyncio
import gc
import pytest
import weakref
from unittest.mock import AsyncMock, patch

from aiows.server import WebSocketServer
from aiows.websocket import WebSocket


class TestConnectionManagement:
    
    @pytest.fixture
    def server(self):
        return WebSocketServer()
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock()
        mock_ws.recv = AsyncMock()
        mock_ws.send = AsyncMock()
        return mock_ws
    
    def test_set_initialization(self, server):
        assert isinstance(server._connections, set)
        assert len(server._connections) == 0
        assert server._connection_count == 0
        assert server._total_connections == 0
    
    def test_connection_tracking_methods(self, server):
        assert server.get_active_connections_count() == 0
        assert server.get_total_connections_count() == 0
        
        stats = server.get_connection_stats()
        assert stats['active_connections'] == 0
        assert stats['total_connections'] == 0
        assert stats['connection_count_tracked'] == 0
    
    @pytest.mark.asyncio
    async def test_add_remove_connection(self, server, mock_websocket):
        ws_wrapper = WebSocket(mock_websocket)
        
        await server._add_connection(ws_wrapper)
        assert len(server._connections) == 1
        assert server._connection_count == 1
        assert server._total_connections == 1
        assert server.get_active_connections_count() == 1
        
        await server._remove_connection(ws_wrapper)
        assert len(server._connections) == 0
        assert server._connection_count == 0
        assert server._total_connections == 1
    
    @pytest.mark.asyncio
    async def test_set_manual_cleanup(self, server, mock_websocket):
        """Test manual cleanup since we no longer use WeakSet automatic cleanup"""
        ws_wrapper = WebSocket(mock_websocket)
        weak_ref = weakref.ref(ws_wrapper)
        
        await server._add_connection(ws_wrapper)
        assert len(server._connections) == 1
        assert weak_ref() is not None
        
        # With regular set, we need manual cleanup
        await server._remove_connection(ws_wrapper)
        del ws_wrapper
        gc.collect()
        
        assert weak_ref() is None
    
    @pytest.mark.asyncio
    async def test_dead_connections_cleanup(self, server, mock_websocket):
        """Test cleanup of dead/closed connections"""
        connections = []
        for i in range(3):
            mock_ws = AsyncMock()
            mock_ws.closed = False
            ws_wrapper = WebSocket(mock_ws)
            connections.append(ws_wrapper)
            await server._add_connection(ws_wrapper)
        
        assert len(server._connections) == 3
        assert server._connection_count == 3
        
        # Mark WebSocket wrappers as closed to simulate closed connections
        connections[0]._is_closed = True  
        connections[1]._is_closed = True
        
        await server._cleanup_dead_connections()
        
        assert len(server._connections) == 1
        assert server._connection_count == 1
    
    @pytest.mark.asyncio
    async def test_periodic_cleanup_task(self, server):
        server._cleanup_interval = 0.1
        
        await server._start_periodic_cleanup()
        assert server._cleanup_task is not None
        assert not server._cleanup_task.done()
        
        await asyncio.sleep(0.2)
        assert not server._cleanup_task.done()
        
        await server._stop_periodic_cleanup()
        assert server._cleanup_task.done()
    
    @pytest.mark.asyncio
    async def test_comprehensive_connection_cleanup(self, server, mock_websocket):
        mock_dispatcher = AsyncMock()
        server.dispatcher = mock_dispatcher
        
        ws_wrapper = WebSocket(mock_websocket)
        
        with patch.object(server, '_add_connection') as mock_add, \
             patch.object(server, '_remove_connection') as mock_remove:
            
            try:
                await server._add_connection(ws_wrapper)
                mock_add.assert_called_once_with(ws_wrapper)
                raise Exception("Test exception")
            except:
                pass
            
            await server.dispatcher.dispatch_disconnect(ws_wrapper, "Connection closed")
            await server._remove_connection(ws_wrapper)
            if not ws_wrapper.closed:
                await ws_wrapper.close()
    
    @pytest.mark.asyncio
    async def test_error_handling_in_connection_cleanup(self, server, mock_websocket):
        ws_wrapper = WebSocket(mock_websocket)
        
        await server._add_connection(ws_wrapper)
        server.dispatcher.dispatch_disconnect = AsyncMock(side_effect=Exception("Dispatch error"))
        ws_wrapper.close = AsyncMock(side_effect=Exception("Close error"))
        
        with patch.object(server, '_remove_connection') as mock_remove:
            try:
                await server.dispatcher.dispatch_disconnect(ws_wrapper, "Test")
            except:
                pass
            
            try:
                await ws_wrapper.close()
            except:
                pass
            
            await server._remove_connection(ws_wrapper)
            mock_remove.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_graceful_shutdown_with_connections(self, server):
        mock_connections = []
        for i in range(3):
            mock_ws = AsyncMock()
            mock_ws.closed = False
            mock_ws.close = AsyncMock()
            ws_wrapper = WebSocket(mock_ws)
            mock_connections.append(ws_wrapper)
            await server._add_connection(ws_wrapper)
        
        assert len(server._connections) == 3
        
        with patch.object(server, '_close_connection_gracefully', new_callable=AsyncMock) as mock_close:
            await server._close_all_connections(timeout=1.0)
            assert mock_close.call_count == 3
    
    @pytest.mark.asyncio
    async def test_connection_stats_accuracy(self, server, mock_websocket):
        initial_stats = server.get_connection_stats()
        assert initial_stats['active_connections'] == 0
        assert initial_stats['total_connections'] == 0
        
        connections = []
        for i in range(5):
            mock_ws = AsyncMock()
            mock_ws.closed = False
            ws_wrapper = WebSocket(mock_ws)
            connections.append(ws_wrapper)
            await server._add_connection(ws_wrapper)
        
        stats = server.get_connection_stats()
        assert stats['active_connections'] == 5
        assert stats['total_connections'] == 5
        assert stats['connection_count_tracked'] == 5
        
        for i in range(2):
            await server._remove_connection(connections[i])
        
        stats = server.get_connection_stats()
        assert stats['active_connections'] == 3
        assert stats['total_connections'] == 5
        assert stats['connection_count_tracked'] == 3
    
    @pytest.mark.asyncio
    async def test_memory_leak_prevention(self, server):
        initial_count = len(server._connections)
        
        for i in range(100):
            mock_ws = AsyncMock()
            mock_ws.closed = False
            ws_wrapper = WebSocket(mock_ws)
            await server._add_connection(ws_wrapper)
            await server._remove_connection(ws_wrapper)
            del ws_wrapper
        
        gc.collect()
        
        assert len(server._connections) == initial_count
        assert server._connection_count == 0
        assert server._total_connections == 100
    
    @pytest.mark.asyncio
    async def test_set_with_real_gc(self, server):
        """Test regular set behavior with garbage collection"""
        mock_ws = AsyncMock()
        mock_ws.closed = False
        ws_wrapper = WebSocket(mock_ws)
        weak_ref = weakref.ref(ws_wrapper)
        
        await server._add_connection(ws_wrapper)
        assert len(server._connections) == 1
        assert weak_ref() is not None
        
        # With regular set, manual cleanup needed
        await server._remove_connection(ws_wrapper)
        del ws_wrapper
        del mock_ws
        
        gc.collect()
        
        assert weak_ref() is None
        assert len(server._connections) == 0
    
    @pytest.mark.asyncio
    async def test_cleanup_interval_configuration(self, server):
        assert server._cleanup_interval == 30.0
        
        server._cleanup_interval = 5.0
        assert server._cleanup_interval == 5.0
    
    @pytest.mark.asyncio
    async def test_server_shutdown_stops_cleanup(self, server):
        await server._start_periodic_cleanup()
        cleanup_task = server._cleanup_task
        
        assert cleanup_task is not None
        assert not cleanup_task.done()
        
        await server.shutdown()
        
        assert cleanup_task.done()


class TestConnectionMemoryManagement:
    
    @pytest.fixture
    def server(self):
        return WebSocketServer()
    
    @pytest.mark.asyncio
    async def test_no_memory_leak_on_connection_error(self, server):
        initial_connections = len(server._connections)
        
        for i in range(50):
            mock_ws = AsyncMock()
            mock_ws.closed = False
            ws_wrapper = WebSocket(mock_ws)
            
            await server._add_connection(ws_wrapper)
            
            try:
                raise ConnectionError("Simulated connection error")
            except:
                await server._remove_connection(ws_wrapper)
                if not ws_wrapper.closed:
                    try:
                        await ws_wrapper.close()
                    except:
                        pass
            
            del ws_wrapper
        
        gc.collect()
        
        assert len(server._connections) == initial_connections
        assert server._connection_count == 0
    
    @pytest.mark.asyncio
    async def test_set_handles_circular_references(self, server):
        """Test that regular set works with circular references when manually cleaned"""
        mock_ws = AsyncMock()
        mock_ws.closed = False
        ws_wrapper = WebSocket(mock_ws)
        
        ws_wrapper.circular_ref = ws_wrapper
        
        weak_ref = weakref.ref(ws_wrapper)
        await server._add_connection(ws_wrapper)
        
        assert len(server._connections) == 1
        assert weak_ref() is not None
        
        # Manual cleanup needed with regular set
        await server._remove_connection(ws_wrapper)
        del ws_wrapper
        gc.collect()
        
        assert weak_ref() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 