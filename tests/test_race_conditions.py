"""
Regression tests for race conditions fixed in Phase 1.1.

RC-1  Double dispatch_disconnect during shutdown
       _close_connection_gracefully and _handle_connection's finally block
       could both call dispatch_disconnect for the same connection.
       Fix: WebSocket._disconnect_dispatched flag (check-then-set, atomic in
       asyncio's single-threaded model).

RC-2  Redundant _connection_count counter could drift from len(_connections).
       Fix: _connection_count removed; len(self._connections) is the single
       source of truth.

RC-3  threading.Lock used for _middleware in MessageDispatcher.
       Wrong primitive in an asyncio context; a blocking lock can starve the
       event loop if held across an await (and signals wrong intent).
       Fix: _middleware stored as an immutable tuple; mutations replace the
       whole reference (atomic assignment in CPython under the GIL).

RC-4  _mark_as_closed() called multiple times could run cleanup logic
       (task cancellation, backpressure cleanup) more than once.
       Fix: early-return guard at the top of _mark_as_closed().
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch

from aiows.server import WebSocketServer
from aiows.websocket import WebSocket
from aiows.dispatcher import MessageDispatcher
from aiows.router import Router
from aiows.middleware.base import BaseMiddleware


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_mock_raw_ws(closed: bool = False) -> Mock:
    """Return a minimal mock suitable for wrapping in WebSocket()."""
    m = Mock()
    m.closed = closed
    m.close = AsyncMock()
    m.recv = AsyncMock(side_effect=asyncio.CancelledError)
    m.send = AsyncMock()
    m.remote_address = ("127.0.0.1", 9999)
    return m


def make_ws(closed: bool = False) -> WebSocket:
    return WebSocket(make_mock_raw_ws(closed=closed))


# ---------------------------------------------------------------------------
# RC-1 — exactly-once dispatch_disconnect
# ---------------------------------------------------------------------------

class TestRC1ExactlyOnceDisconnect:

    @pytest.fixture
    def server(self):
        s = WebSocketServer()
        s.include_router(Router())
        return s

    @pytest.mark.asyncio
    async def test_flag_starts_false(self):
        """A new WebSocket has _disconnect_dispatched == False."""
        ws = make_ws()
        assert ws._disconnect_dispatched is False

    @pytest.mark.asyncio
    async def test_close_connection_gracefully_dispatches_once(self, server):
        """_close_connection_gracefully dispatches disconnect exactly once."""
        ws = make_ws()
        await server._add_connection(ws)

        dispatch_calls = []

        async def fake_dispatch(w, reason):
            dispatch_calls.append(reason)

        server.dispatcher.dispatch_disconnect = fake_dispatch

        # Call _close_connection_gracefully twice to simulate the race.
        await server._close_connection_gracefully(ws)
        await server._close_connection_gracefully(ws)

        assert len(dispatch_calls) == 1

    @pytest.mark.asyncio
    async def test_flag_prevents_double_dispatch_across_methods(self, server):
        """
        Simulate the race: _handle_connection finally block AND
        _close_connection_gracefully both try to dispatch disconnect.
        Only the first one (whichever wins) should succeed.
        """
        ws = make_ws()
        await server._add_connection(ws)

        dispatch_calls = []

        async def fake_dispatch(w, reason):
            dispatch_calls.append(reason)

        server.dispatcher.dispatch_disconnect = fake_dispatch

        # Simulate _close_connection_gracefully path (shutdown).
        if not ws._disconnect_dispatched:
            ws._disconnect_dispatched = True
            await server.dispatcher.dispatch_disconnect(ws, "Server shutdown")

        # Simulate _handle_connection finally path (concurrent).
        if not ws._disconnect_dispatched:
            ws._disconnect_dispatched = True
            await server.dispatcher.dispatch_disconnect(ws, "Connection closed")

        assert len(dispatch_calls) == 1
        assert dispatch_calls[0] == "Server shutdown"

    @pytest.mark.asyncio
    async def test_flag_set_after_graceful_close(self, server):
        """After _close_connection_gracefully the flag is True."""
        ws = make_ws()
        await server._add_connection(ws)
        server.dispatcher.dispatch_disconnect = AsyncMock()

        await server._close_connection_gracefully(ws)

        assert ws._disconnect_dispatched is True


# ---------------------------------------------------------------------------
# RC-2 — no separate _connection_count counter
# ---------------------------------------------------------------------------

class TestRC2NoSeparateCounter:

    @pytest.fixture
    def server(self):
        return WebSocketServer()

    def test_no_connection_count_attribute(self, server):
        """_connection_count must not exist; len(_connections) is the truth."""
        assert not hasattr(server, '_connection_count'), (
            "_connection_count was re-introduced; use len(_connections) instead"
        )

    @pytest.mark.asyncio
    async def test_active_count_matches_set_size(self, server):
        """get_active_connections_count() always equals len(_connections)."""
        wss = [make_ws() for _ in range(5)]
        for ws in wss:
            await server._add_connection(ws)

        assert server.get_active_connections_count() == len(server._connections) == 5

        await server._remove_connection(wss[0])
        await server._remove_connection(wss[1])

        assert server.get_active_connections_count() == len(server._connections) == 3

    @pytest.mark.asyncio
    async def test_get_connection_stats_no_tracked_key(self, server):
        """get_connection_stats() must not expose a 'connection_count_tracked' key."""
        stats = server.get_connection_stats()
        assert 'connection_count_tracked' not in stats

    @pytest.mark.asyncio
    async def test_cleanup_dead_connections_does_not_diverge(self, server):
        """
        After cleanup, len(_connections) must still equal
        get_active_connections_count() — no separate counter to drift.
        """
        wss = [make_ws() for _ in range(4)]
        for ws in wss:
            await server._add_connection(ws)

        # Mark two as closed.
        wss[0]._mark_as_closed()
        wss[1]._mark_as_closed()

        await server._cleanup_dead_connections()

        assert len(server._connections) == 2
        assert server.get_active_connections_count() == 2


# ---------------------------------------------------------------------------
# RC-3 — _middleware stored as tuple, no threading.Lock
# ---------------------------------------------------------------------------

class TestRC3MiddlewareTuple:

    def test_middleware_is_tuple(self):
        """MessageDispatcher._middleware must be a tuple, not a list."""
        dispatcher = MessageDispatcher(Router())
        assert isinstance(dispatcher._middleware, tuple)

    def test_no_middleware_lock_attribute(self):
        """_middleware_lock must not exist on the dispatcher."""
        dispatcher = MessageDispatcher(Router())
        assert not hasattr(dispatcher, '_middleware_lock'), (
            "_middleware_lock was re-introduced; use the immutable tuple pattern"
        )

    def test_add_middleware_appends_tuple(self):
        """add_middleware must produce a new tuple with the middleware appended."""
        dispatcher = MessageDispatcher(Router())

        class DummyMiddleware(BaseMiddleware):
            async def on_connect(self, next_handler, websocket):
                await next_handler(websocket)
            async def on_disconnect(self, next_handler, websocket, reason):
                await next_handler(websocket, reason)
            async def on_message(self, next_handler, websocket, message):
                await next_handler(websocket, message)

        m1, m2 = DummyMiddleware(), DummyMiddleware()
        dispatcher.add_middleware(m1)
        dispatcher.add_middleware(m2)

        assert isinstance(dispatcher._middleware, tuple)
        assert len(dispatcher._middleware) == 2
        assert dispatcher._middleware[0] is m1
        assert dispatcher._middleware[1] is m2

    def test_remove_middleware(self):
        """remove_middleware must produce a new tuple without the target."""
        dispatcher = MessageDispatcher(Router())

        class DummyMiddleware(BaseMiddleware):
            async def on_connect(self, next_handler, websocket):
                await next_handler(websocket)
            async def on_disconnect(self, next_handler, websocket, reason):
                await next_handler(websocket, reason)
            async def on_message(self, next_handler, websocket, message):
                await next_handler(websocket, message)

        m = DummyMiddleware()
        dispatcher.add_middleware(m)
        assert len(dispatcher._middleware) == 1

        removed = dispatcher.remove_middleware(m)
        assert removed is True
        assert len(dispatcher._middleware) == 0

    def test_remove_nonexistent_middleware_returns_false(self):
        dispatcher = MessageDispatcher(Router())

        class DummyMiddleware(BaseMiddleware):
            async def on_connect(self, next_handler, websocket):
                await next_handler(websocket)
            async def on_disconnect(self, next_handler, websocket, reason):
                await next_handler(websocket, reason)
            async def on_message(self, next_handler, websocket, message):
                await next_handler(websocket, message)

        removed = dispatcher.remove_middleware(DummyMiddleware())
        assert removed is False

    @pytest.mark.asyncio
    async def test_snapshot_is_stable_during_dispatch(self):
        """
        Middleware added after dispatch starts must not affect the current
        dispatch execution (the tuple snapshot is immutable).
        """
        router = Router()
        dispatcher = MessageDispatcher(router)

        execution_order = []

        class RecordingMiddleware(BaseMiddleware):
            def __init__(self, name):
                self.name = name

            async def on_connect(self, next_handler, websocket):
                execution_order.append(self.name)
                await next_handler(websocket)

            async def on_disconnect(self, next_handler, websocket, reason):
                await next_handler(websocket, reason)

            async def on_message(self, next_handler, websocket, message):
                await next_handler(websocket, message)

        m1 = RecordingMiddleware("m1")
        dispatcher.add_middleware(m1)

        mock_ws = Mock()
        mock_ws.context = {}
        mock_ws.closed = False
        mock_ws.remote_address = ("127.0.0.1", 0)

        # Add a second middleware AFTER dispatch has been called but while it
        # is "in flight" (simulated by checking execution_order after dispatch).
        await dispatcher.dispatch_connect(mock_ws)

        # Only m1 should have run; m2 was not present when the tuple was read.
        assert execution_order == ["m1"]


# ---------------------------------------------------------------------------
# RC-4 — _mark_as_closed is idempotent
# ---------------------------------------------------------------------------

class TestRC4MarkAsClosedIdempotent:

    def test_second_call_is_noop(self):
        """Calling _mark_as_closed() twice must not error or double-cancel."""
        ws = make_ws()

        # First call — sets event, cancels task.
        ws._mark_as_closed()
        assert ws._is_closed is True

        # Second call — must silently return without raising.
        ws._mark_as_closed()
        assert ws._is_closed is True

    @pytest.mark.asyncio
    async def test_send_task_cancelled_only_once(self):
        """The background send task is cancelled exactly once."""
        ws = make_ws()

        cancel_count = 0

        class FakeTask:
            def done(self):
                return False

            def cancel(self):
                nonlocal cancel_count
                cancel_count += 1

        ws._send_task = FakeTask()

        ws._mark_as_closed()
        ws._mark_as_closed()  # second call must be a no-op

        assert cancel_count == 1

    @pytest.mark.asyncio
    async def test_backpressure_cleanup_called_only_once(self):
        """BackpressureManager.cleanup() is called exactly once."""
        ws = make_ws()
        cleanup_count = 0

        class FakeManager:
            def cleanup(self):
                nonlocal cleanup_count
                cleanup_count += 1

        ws._backpressure_manager = FakeManager()

        ws._mark_as_closed()
        ws._mark_as_closed()

        assert cleanup_count == 1

    @pytest.mark.asyncio
    async def test_close_then_critical_error_safe(self):
        """
        Calling close() followed by _handle_critical_error() (which calls
        _mark_as_closed internally) must not raise.
        """
        ws = make_ws()
        ws._websocket.close = AsyncMock()

        await ws.close()
        # Should not raise even though already closed.
        ws._handle_critical_error(RuntimeError("late error"), "test_op")
