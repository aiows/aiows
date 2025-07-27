import asyncio
import pytest
import copy
import time
from unittest.mock import AsyncMock

from aiows import Router, MessageDispatcher, WebSocket, BaseMiddleware
from aiows.exceptions import MessageValidationError, MiddlewareError, ConnectionError


class MockMiddleware(BaseMiddleware):
    
    def __init__(self, name: str, should_fail: bool = False, fail_on: str = None):
        self.name = name
        self.should_fail = should_fail
        self.fail_on = fail_on
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.message_calls = 0
    
    async def on_connect(self, next_handler, websocket):
        self.connect_calls += 1
        if self.should_fail and self.fail_on == "connect":
            raise MiddlewareError(f"Middleware {self.name} failed on connect")
        return await next_handler(websocket)
    
    async def on_disconnect(self, next_handler, websocket, reason):
        self.disconnect_calls += 1
        if self.should_fail and self.fail_on == "disconnect":
            raise MiddlewareError(f"Middleware {self.name} failed on disconnect")
        return await next_handler(websocket, reason)
    
    async def on_message(self, next_handler, websocket, message_data):
        self.message_calls += 1
        if self.should_fail and self.fail_on == "message":
            raise MiddlewareError(f"Middleware {self.name} failed on message")
        return await next_handler(websocket, message_data)


class TestDispatcherThreadSafety:
    
    @pytest.fixture
    def mock_websocket(self):
        mock_ws = AsyncMock()
        mock_ws.closed = False
        mock_ws.close = AsyncMock()
        return mock_ws
    
    @pytest.fixture
    def websocket_wrapper(self, mock_websocket):
        return WebSocket(mock_websocket)
    
    @pytest.fixture
    def router(self):
        router = Router()
        
        async def connect_handler(ws):
            pass
        
        async def disconnect_handler(ws, reason):
            pass
        
        async def message_handler(ws, message):
            pass
        
        router._connect_handlers = [connect_handler]
        router._disconnect_handlers = [disconnect_handler]
        router._message_handlers = [{'message_type': None, 'handler': message_handler}]
        
        return router
    
    @pytest.fixture
    def dispatcher(self, router):
        return MessageDispatcher(router)
    
    @pytest.mark.asyncio
    async def test_concurrent_middleware_addition(self, dispatcher):
        
        async def add_middleware_task(task_id):
            middleware = MockMiddleware(f"middleware_{task_id}")
            dispatcher.add_middleware(middleware)
            return f"added_{task_id}"
        
        tasks = [add_middleware_task(i) for i in range(10)]
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 10
        assert all(r.startswith("added_") for r in results)
        
        assert len(dispatcher._middleware) == 10
        for i, middleware in enumerate(dispatcher._middleware):
            assert middleware.name == f"middleware_{i}"
    
    @pytest.mark.asyncio 
    async def test_concurrent_message_processing(self, dispatcher, websocket_wrapper):
        
        dispatcher.add_middleware(MockMiddleware("mw1"))
        dispatcher.add_middleware(MockMiddleware("mw2"))
        
        async def process_message_task(task_id):
            try:
                message_data = {
                    "type": "chat",
                    "text": f"message_{task_id}",
                    "user_id": task_id,
                    "timestamp": "2024-01-01T00:00:00Z"
                }
                await dispatcher.dispatch_message(websocket_wrapper, message_data)
                return f"processed_{task_id}"
            except Exception as e:
                return f"error_{task_id}: {e}"
        
        tasks = [process_message_task(i) for i in range(20)]
        results = await asyncio.gather(*tasks)
        
        success_count = sum(1 for r in results if r.startswith("processed_"))
        assert success_count == 20
        
        assert dispatcher._middleware[0].message_calls == 20
        assert dispatcher._middleware[1].message_calls == 20
    
    @pytest.mark.asyncio
    async def test_message_data_defensive_copying(self, dispatcher, websocket_wrapper):
        
        original_data = {
            "type": "chat",
            "text": "original_message",
            "user_id": 123,
            "nested": {"data": "value"}
        }
        
        class ModifyingMiddleware(BaseMiddleware):
            async def on_message(self, next_handler, websocket, message_data):
                message_data["text"] = "modified_message"
                message_data["nested"]["data"] = "modified_value"
                return await next_handler(websocket, message_data)
        
        dispatcher.add_middleware(ModifyingMiddleware())
        
        tasks = []
        for i in range(5):
            task_data = copy.deepcopy(original_data)
            task_data["user_id"] = i
            tasks.append(dispatcher.dispatch_message(websocket_wrapper, task_data))
        
        await asyncio.gather(*tasks)
        
        assert original_data["text"] == "original_message"
        assert original_data["nested"]["data"] == "value"
    
    @pytest.mark.asyncio
    async def test_middleware_chain_memory_leak_prevention(self, dispatcher, websocket_wrapper):
        
        for i in range(50):
            dispatcher.add_middleware(MockMiddleware(f"mw_{i}"))
        
        for i in range(100):
            message_data = {
                "type": "chat", 
                "text": f"message_{i}",
                "user_id": i
            }
            await dispatcher.dispatch_message(websocket_wrapper, message_data)
        
        assert len(dispatcher._middleware) == 50
    
    @pytest.mark.asyncio
    async def test_selective_exception_handling(self, dispatcher, websocket_wrapper):
        
        class ExceptionMiddleware(BaseMiddleware):
            def __init__(self, exception_type):
                self.exception_type = exception_type
            
            async def on_message(self, next_handler, websocket, message_data):
                if self.exception_type == "middleware":
                    raise MiddlewareError("Test middleware error")
                elif self.exception_type == "connection":
                    raise ConnectionError("Test connection error") 
                elif self.exception_type == "validation":
                    raise MessageValidationError("Test validation error")
                elif self.exception_type == "timeout":
                    raise asyncio.TimeoutError("Test timeout")
                elif self.exception_type == "unexpected":
                    raise ValueError("Unexpected error")
                return await next_handler(websocket, message_data)
        
        message_data = {"type": "chat", "text": "test", "user_id": 1}
        
        dispatcher.add_middleware(ExceptionMiddleware("middleware"))
        try:
            await dispatcher.dispatch_message(websocket_wrapper, message_data)
        except MiddlewareError:
            pytest.fail("MiddlewareError should be handled, not raised")
        
        dispatcher._middleware.clear()
        
        dispatcher.add_middleware(ExceptionMiddleware("unexpected"))
        with pytest.raises(ValueError, match="Unexpected error"):
            await dispatcher.dispatch_message(websocket_wrapper, message_data)
    
    @pytest.mark.asyncio
    async def test_mixed_concurrent_operations(self, dispatcher, websocket_wrapper):
        
        dispatcher.add_middleware(MockMiddleware("test_mw"))
        
        async def connect_task():
            try:
                await dispatcher.dispatch_connect(websocket_wrapper)
                return "connect_ok"
            except Exception as e:
                return f"connect_error: {e}"
        
        async def disconnect_task():
            try:
                await dispatcher.dispatch_disconnect(websocket_wrapper, "test")
                return "disconnect_ok"
            except Exception as e:
                return f"disconnect_error: {e}"
        
        async def message_task(msg_id):
            try:
                message_data = {"type": "chat", "text": f"msg_{msg_id}", "user_id": msg_id}
                await dispatcher.dispatch_message(websocket_wrapper, message_data)
                return f"message_ok_{msg_id}"
            except Exception as e:
                return f"message_error_{msg_id}: {e}"
        
        tasks = [
            connect_task(),
            message_task(1), message_task(2),
            disconnect_task(),
            message_task(3), message_task(4)
        ]
        
        results = await asyncio.gather(*tasks)
        
        assert len(results) == 6
        success_count = sum(1 for r in results if not r.endswith("error"))
        assert success_count >= 5  
    
    @pytest.mark.asyncio
    async def test_state_consistency_under_load(self, dispatcher):
        
        async def add_middleware_continuously():
            for i in range(10):
                dispatcher.add_middleware(MockMiddleware(f"load_mw_{i}"))
                await asyncio.sleep(0.01)
        
        async def process_messages_continuously():
            mock_ws = AsyncMock()
            mock_ws.closed = False
            ws_wrapper = WebSocket(mock_ws)
            
            for i in range(20):
                message_data = {"type": "chat", "text": f"load_msg_{i}", "user_id": i}
                try:
                    await dispatcher.dispatch_message(ws_wrapper, message_data)
                except Exception:
                    pass  
                await asyncio.sleep(0.005)  
        
        await asyncio.gather(
            add_middleware_continuously(),
            process_messages_continuously()
        )
        
        assert len(dispatcher._middleware) == 10
        
        for i, middleware in enumerate(dispatcher._middleware):
            assert middleware.name == f"load_mw_{i}"
    
    @pytest.mark.asyncio
    async def test_performance_no_significant_degradation(self, dispatcher, websocket_wrapper):
        
        dispatcher.add_middleware(MockMiddleware("perf_test"))
        
        start_time = time.time()
        for i in range(100):
            message_data = {"type": "chat", "text": f"seq_{i}", "user_id": i}
            await dispatcher.dispatch_message(websocket_wrapper, message_data)
        sequential_time = time.time() - start_time
        
        dispatcher._middleware[0].message_calls = 0
        
        start_time = time.time()
        batch_size = 10
        for i in range(0, 100, batch_size):
            tasks = []
            for j in range(i, min(i + batch_size, 100)):
                message_data = {"type": "chat", "text": f"conc_{j}", "user_id": j}
                tasks.append(dispatcher.dispatch_message(websocket_wrapper, message_data))
            await asyncio.gather(*tasks)
        concurrent_time = time.time() - start_time
        
        max_allowed_ratio = 3.0  
        actual_ratio = concurrent_time / sequential_time if sequential_time > 0 else 1.0
        
        assert actual_ratio <= max_allowed_ratio, (
            f"Performance degradation too high: {actual_ratio:.2f}x slower "
            f"(max allowed: {max_allowed_ratio}x)"
        )
        
        assert dispatcher._middleware[0].message_calls == 100
    
    @pytest.mark.asyncio
    async def test_message_parsing_with_invalid_data(self, dispatcher, websocket_wrapper):
        
        invalid_data_sets = [
            {"type": "chat"},
            {"type": "unknown_type", "data": "test"},
            {"text": "no type field"},
            {},
            {"type": "chat", "user_id": "not_a_number", "text": "test"}
        ]
        
        results = []
        for i, invalid_data in enumerate(invalid_data_sets):
            try:
                await dispatcher.dispatch_message(websocket_wrapper, invalid_data)
                results.append(f"success_{i}")
            except MessageValidationError:
                results.append(f"validation_error_{i}")
            except Exception as e:
                results.append(f"unexpected_error_{i}: {e}")
        
        validation_errors = sum(1 for r in results if "validation_error" in r)
        assert validation_errors >= 4  
    
    @pytest.mark.asyncio
    async def test_asyncio_exception_propagation(self, dispatcher, websocket_wrapper):
        
        class AsyncioExceptionMiddleware(BaseMiddleware):
            async def on_message(self, next_handler, websocket, message_data):
                raise asyncio.CancelledError("Operation cancelled")
        
        dispatcher.add_middleware(AsyncioExceptionMiddleware())
        
        with pytest.raises(asyncio.CancelledError):
            message_data = {"type": "chat", "text": "test", "user_id": 1}
            await dispatcher.dispatch_message(websocket_wrapper, message_data)
    
    @pytest.mark.asyncio
    async def test_critical_middleware_failure_handling(self, dispatcher, websocket_wrapper):
        
        class AuthMiddleware(BaseMiddleware):
            async def on_connect(self, next_handler, websocket):
                raise MiddlewareError("Authentication failed")
        
        dispatcher.add_middleware(AuthMiddleware())
        
        await dispatcher.dispatch_connect(websocket_wrapper)
        
        websocket_wrapper._websocket.close.assert_called_once()
        args, kwargs = websocket_wrapper._websocket.close.call_args
        assert kwargs.get('code') == 1011  
        assert kwargs.get('reason') == "Server error" 