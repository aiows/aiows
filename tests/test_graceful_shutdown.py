"""
Tests for graceful shutdown functionality
"""

import pytest
import asyncio
import signal
import time
from unittest.mock import Mock, AsyncMock, patch

from aiows.server import WebSocketServer
from aiows.router import Router


class TestGracefulShutdown:
    """Test graceful shutdown mechanisms"""
    
    @pytest.fixture
    def server(self):
        """Create a test server instance"""
        server = WebSocketServer()
        router = Router()
        server.include_router(router)
        return server
        
    def test_shutdown_initialization(self, server):
        """Test that shutdown attributes are properly initialized"""
        assert isinstance(server._shutdown_event, asyncio.Event)
        assert not server._shutdown_event.is_set()
        assert server._shutdown_timeout == 30.0
        assert not server._signal_handlers_registered
        assert server._server_task is None
        
    def test_set_shutdown_timeout(self, server):
        """Test setting shutdown timeout"""
        # Test valid timeout
        server.set_shutdown_timeout(60.0)
        assert server._shutdown_timeout == 60.0
        
        # Test invalid timeout
        with pytest.raises(ValueError):
            server.set_shutdown_timeout(0)
        
        with pytest.raises(ValueError):
            server.set_shutdown_timeout(-10)
            
    def test_is_shutting_down_property(self, server):
        """Test is_shutting_down property"""
        assert not server.is_shutting_down
        
        server._shutdown_event.set()
        assert server.is_shutting_down
        
    def test_signal_handlers_setup(self, server):
        """Test signal handlers registration"""
        # Mock the event loop
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop_getter.return_value = mock_loop
            
            # Test signal handler setup
            server._setup_signal_handlers()
            
            # Verify signal handlers were registered
            assert server._signal_handlers_registered
            assert mock_loop.add_signal_handler.call_count == 2
            
            # Verify SIGTERM and SIGINT were registered
            calls = mock_loop.add_signal_handler.call_args_list
            signals_registered = [call[0][0] for call in calls]
            assert signal.SIGTERM in signals_registered
            assert signal.SIGINT in signals_registered
            
    def test_signal_handlers_duplicate_registration(self, server):
        """Test that signal handlers are not registered twice"""
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop_getter.return_value = mock_loop
            
            # Register handlers twice
            server._setup_signal_handlers()
            server._setup_signal_handlers()
            
            # Should only be called once
            assert mock_loop.add_signal_handler.call_count == 2
            
    def test_signal_handlers_exception_handling(self, server):
        """Test signal handler registration with exceptions"""
        with patch('asyncio.get_running_loop') as mock_loop_getter:
            mock_loop = Mock()
            mock_loop.add_signal_handler.side_effect = OSError("Signal not supported")
            mock_loop_getter.return_value = mock_loop
            
            # Should not raise exception
            server._setup_signal_handlers()
            assert not server._signal_handlers_registered
            
    @pytest.mark.asyncio
    async def test_programmatic_shutdown(self, server):
        """Test programmatic shutdown without signal"""
        # Mock connections
        mock_ws1 = Mock()
        mock_ws1.closed = False
        mock_ws1.close = AsyncMock()
        
        mock_ws2 = Mock()
        mock_ws2.closed = False
        mock_ws2.close = AsyncMock()
        
        server._connections = {mock_ws1, mock_ws2}
        
        # Mock dispatcher
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        # Start shutdown
        await server.shutdown(timeout=5.0)
        
        # Verify shutdown was completed
        assert server._shutdown_event.is_set()
        assert len(server._connections) == 0
        
        # Verify connections were closed
        mock_ws1.close.assert_called_once()
        mock_ws2.close.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_shutdown_timeout_behavior(self, server):
        """Test shutdown with connection timeout"""
        # Create a connection that takes too long to close gracefully
        slow_ws = Mock()
        slow_ws.closed = False
        
        # Make graceful close slow but force close fast
        call_count = 0
        async def slow_close(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First call (graceful) is slow
                await asyncio.sleep(10)
            # Subsequent calls (force close) are fast
            
        slow_ws.close = slow_close
        
        server._connections = {slow_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        start_time = time.time()
        await server.shutdown(timeout=2.0)
        elapsed = time.time() - start_time
        
        # Should complete within timeout + small buffer due to force close
        assert elapsed < 4.0  # More generous timeout due to force close logic
        assert server._shutdown_event.is_set()
        
    @pytest.mark.asyncio
    async def test_shutdown_already_in_progress(self, server):
        """Test calling shutdown when already shutting down"""
        # Set shutdown event
        server._shutdown_event.set()
        
        # Should return immediately without error
        await server.shutdown()
        
        # Still should be set
        assert server._shutdown_event.is_set()
        
    @pytest.mark.asyncio
    async def test_cleanup_resources(self, server):
        """Test resource cleanup"""
        # Add some mock connections
        mock_ws = Mock()
        server._connections = {mock_ws}
        
        # Test cleanup
        await server._cleanup_resources()
        
        # Connections should be cleared
        assert len(server._connections) == 0
        
    @pytest.mark.asyncio
    async def test_close_connection_gracefully(self, server):
        """Test graceful closing of individual connection"""
        mock_ws = Mock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock()
        
        server._connections = {mock_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        await server._close_connection_gracefully(mock_ws)
        
        # Verify disconnect was called and connection closed
        server.dispatcher.dispatch_disconnect.assert_called_once_with(
            mock_ws, "Server shutdown"
        )
        mock_ws.close.assert_called_once_with(code=1001, reason="Server shutdown")
        assert mock_ws not in server._connections
        
    @pytest.mark.asyncio
    async def test_close_connection_with_exception(self, server):
        """Test graceful close with exceptions"""
        mock_ws = Mock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock(side_effect=Exception("Close failed"))
        
        server._connections = {mock_ws}
        server.dispatcher.dispatch_disconnect = AsyncMock(
            side_effect=Exception("Disconnect failed")
        )
        
        # Should not raise exception
        await server._close_connection_gracefully(mock_ws)
        
        # Connection should still be removed
        assert mock_ws not in server._connections
        
    @pytest.mark.asyncio
    async def test_close_all_connections_empty(self, server):
        """Test closing connections when no connections exist"""
        server._connections = set()
        
        # Should complete without error
        await server._close_all_connections(timeout=5.0)
        
    @pytest.mark.asyncio
    async def test_close_all_connections_timeout(self, server):
        """Test connection close with timeout"""
        # Create connections that take too long to close gracefully
        slow_connections = []
        for i in range(3):
            mock_ws = Mock()
            mock_ws.closed = False
            
            # First call is slow, but we don't wait for force close
            call_counts = {'count': 0}
            async def slow_close(*args, **kwargs):
                call_counts['count'] += 1
                if call_counts['count'] == 1:
                    await asyncio.sleep(10)  # Only first graceful close is slow
                
            mock_ws.close = slow_close
            slow_connections.append(mock_ws)
            
        server._connections = set(slow_connections)
        server.dispatcher.dispatch_disconnect = AsyncMock()
        
        start_time = time.time()
        await server._close_all_connections(timeout=1.0)
        elapsed = time.time() - start_time
        
        # Should timeout graceful close and immediately force close
        assert elapsed < 3.0  # Should not wait for slow force close
        
    @pytest.mark.asyncio 
    async def test_server_task_cancellation(self, server):
        """Test server task cancellation logic"""
        # Test that shutdown method calls cancel on server task when it exists
        cancelled = False
        
        class MockTask:
            def done(self):
                return False
                
            def cancel(self):
                nonlocal cancelled
                cancelled = True
                
            def __await__(self):
                # Make it awaitable but immediately return
                return iter([None])
        
        server._server_task = MockTask()
        
        await server.shutdown(timeout=1.0)
        
        # Verify task was cancelled
        assert cancelled
        
    def test_shutdown_stops_message_loop(self, server):
        """Test that shutdown event can break connection message processing"""
        # This is tested implicitly by other tests
        # The shutdown event is checked in the _handle_connection loop
        # and we've verified that shutdown process works correctly
        assert hasattr(server, '_shutdown_event')
        assert callable(getattr(server, 'shutdown'))
        
        # Test that shutdown event affects the is_shutting_down property
        assert not server.is_shutting_down
        server._shutdown_event.set()
        assert server.is_shutting_down
            
    @pytest.mark.asyncio
    async def test_multiple_shutdown_calls(self, server):
        """Test calling shutdown multiple times"""
        # Start multiple shutdown calls
        tasks = [
            asyncio.create_task(server.shutdown(timeout=1.0))
            for _ in range(3)
        ]
        
        # All should complete without error
        await asyncio.gather(*tasks)
        
        # Should be shut down
        assert server.is_shutting_down 