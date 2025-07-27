import pytest
import asyncio
import signal
import time
from unittest.mock import Mock, AsyncMock, patch

from aiows.server import WebSocketServer
from aiows.router import Router


class TestGracefulShutdown:
    
    @pytest.fixture
    def server(self):
        server = WebSocketServer()
        router = Router()
        server.include_router(router)
        return server
        
    def test_shutdown_initialization(self, server):
        assert isinstance(server._shutdown_event, asyncio.Event)
        assert not server._shutdown_event.is_set()
        assert server._shutdown_timeout == 30.0
        assert not server._signal_handlers_registered
        assert server._server_task is None
        
    def test_set_shutdown_timeout(self, server):
        server.set_shutdown_timeout(60.0)
        assert server._shutdown_timeout == 60.0
        
        with pytest.raises(ValueError):
            server.set_shutdown_timeout(0)
        
        with pytest.raises(ValueError):
            server.set_shutdown_timeout(-10)
            
    def test_is_shutting_down_property(self, server):
        assert not server.is_shutting_down
        
        server._shutdown_event.set()
        assert server.is_shutting_down
        
    def test_signal_handlers_setup(self, server):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop_getter.return_value = mock_loop
            
            server._setup_signal_handlers()
            
            assert server._signal_handlers_registered
            assert mock_loop.add_signal_handler.call_count == 2
            
            calls = mock_loop.add_signal_handler.call_args_list
            signals_registered = [call[0][0] for call in calls]
            assert signal.SIGTERM in signals_registered
            assert signal.SIGINT in signals_registered
            
    def test_signal_handlers_duplicate_registration(self, server):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop_getter.return_value = mock_loop
            
            server._setup_signal_handlers()
            server._setup_signal_handlers()
            
            assert mock_loop.add_signal_handler.call_count == 2
            
    def test_signal_handlers_exception_handling(self, server):
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop.add_signal_handler.side_effect = OSError("Signal not supported")
            mock_loop_getter.return_value = mock_loop
            
            server._setup_signal_handlers()
            assert not server._signal_handlers_registered
            
    @pytest.mark.asyncio
    async def test_programmatic_shutdown(self, server):
        mock_ws1 = Mock()
        mock_ws1.closed = False
        mock_ws1.close = AsyncMock()
        
        mock_ws2 = Mock()
        mock_ws2.closed = False
        mock_ws2.close = AsyncMock()
        
        server._connections = {mock_ws1, mock_ws2}
        
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        await server.shutdown(timeout=5.0)
        
        assert server._shutdown_event.is_set()
        assert len(server._connections) == 0
        
        mock_ws1.close.assert_called_once()
        mock_ws2.close.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_shutdown_timeout_behavior(self, server):
        slow_ws = Mock()
        slow_ws.closed = False
        
        call_count = 0
        async def slow_close(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                await asyncio.sleep(10)
                
        slow_ws.close = slow_close
        
        server._connections = {slow_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        start_time = time.time()
        await server.shutdown(timeout=2.0)
        elapsed = time.time() - start_time
        
        assert elapsed < 4.0
        assert server._shutdown_event.is_set()
        
    @pytest.mark.asyncio
    async def test_shutdown_already_in_progress(self, server):
        server._shutdown_event.set()
        
        await server.shutdown()
        
        assert server._shutdown_event.is_set()
        
    @pytest.mark.asyncio
    async def test_cleanup_resources(self, server):
        mock_ws = Mock()
        server._connections = {mock_ws}
        
        await server._cleanup_resources()
        
        assert len(server._connections) == 0
        
    @pytest.mark.asyncio
    async def test_close_connection_gracefully(self, server):
        mock_ws = Mock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock()
        
        server._connections = {mock_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        await server._close_connection_gracefully(mock_ws)
        
        server.dispatcher.dispatch_disconnect.assert_called_once_with(
            mock_ws, "Server shutdown"
        )
        mock_ws.close.assert_called_once_with(code=1001, reason="Server shutdown")
        assert mock_ws not in server._connections
        
    @pytest.mark.asyncio
    async def test_close_connection_with_exception(self, server):
        mock_ws = Mock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock(side_effect=Exception("Close failed"))
        
        server._connections = {mock_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock(
            side_effect=Exception("Disconnect failed")
        )
        
        await server._close_connection_gracefully(mock_ws)
        
        assert mock_ws not in server._connections
        
    @pytest.mark.asyncio
    async def test_close_all_connections_empty(self, server):
        server._connections = set()
        
        await server._close_all_connections(timeout=5.0)
        
    @pytest.mark.asyncio
    async def test_close_all_connections_timeout(self, server):
        slow_connections = []
        for i in range(3):
            mock_ws = Mock()
            mock_ws.closed = False
            
            call_counts = {'count': 0}
            async def slow_close(*args, **kwargs):
                call_counts['count'] += 1
                if call_counts['count'] == 1:
                    await asyncio.sleep(10)
                
            mock_ws.close = slow_close
            slow_connections.append(mock_ws)
            
        server._connections = set(slow_connections)
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        start_time = time.time()
        await server._close_all_connections(timeout=1.0)
        elapsed = time.time() - start_time
        
        assert elapsed < 3.0
        
    @pytest.mark.asyncio 
    async def test_server_task_cancellation(self, server):
        cancelled = False
        
        class MockTask:
            def done(self):
                return False
                
            def cancel(self):
                nonlocal cancelled
                cancelled = True
                
            def __await__(self):
                return iter([None])
        
        server._server_task = MockTask()
        
        await server.shutdown(timeout=1.0)
        
        assert cancelled
        
    def test_shutdown_stops_message_loop(self, server):
        assert hasattr(server, '_shutdown_event')
        assert callable(getattr(server, 'shutdown'))
        
        assert not server.is_shutting_down
        server._shutdown_event.set()
        assert server.is_shutting_down
            
    @pytest.mark.asyncio
    async def test_multiple_shutdown_calls(self, server):
        tasks = [
            asyncio.create_task(server.shutdown(timeout=1.0))
            for _ in range(3)
        ]
        
        await asyncio.gather(*tasks)
        
        assert server.is_shutting_down 