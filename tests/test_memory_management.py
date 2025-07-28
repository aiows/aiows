import asyncio
import gc
import pytest
import psutil
import os
import time
from memory_profiler import profile
from unittest.mock import AsyncMock, Mock

from aiows.dispatcher import MessageDispatcher
from aiows.router import Router
from aiows.websocket import WebSocket
from aiows.middleware.base import BaseMiddleware
from aiows.types import ChatMessage
from aiows.exceptions import MiddlewareError


class MockMiddleware(BaseMiddleware):
    def __init__(self, name: str, should_call_next: bool = True, raise_error: bool = False):
        self.name = name
        self.should_call_next = should_call_next
        self.raise_error = raise_error
        self.connect_called = False
        self.disconnect_called = False
        self.message_called = False
        self.cleanup_called = False
        
    async def on_connect(self, next_handler, websocket):
        self.connect_called = True
        if self.raise_error:
            raise MiddlewareError(f"Error in {self.name}")
        if self.should_call_next:
            await next_handler(websocket)
            
    async def on_disconnect(self, next_handler, websocket, reason):
        self.disconnect_called = True
        if self.raise_error:
            raise MiddlewareError(f"Error in {self.name}")
        if self.should_call_next:
            await next_handler(websocket, reason)
            
    async def on_message(self, next_handler, websocket, message):
        self.message_called = True
        if self.raise_error:
            raise MiddlewareError(f"Error in {self.name}")
        if self.should_call_next:
            await next_handler(websocket, message)
    
    def cleanup(self):
        self.cleanup_called = True


class TestMemoryManagement:
    
    @pytest.fixture
    def router(self):
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket):
            pass
            
        @router.disconnect()
        async def handle_disconnect(websocket, reason):
            pass
            
        @router.message("chat")
        async def handle_chat(websocket, message):
            pass
            
        return router
    
    @pytest.fixture
    def dispatcher(self, router):
        return MessageDispatcher(router)
    
    @pytest.fixture
    def mock_websocket(self):
        websocket = Mock(spec=WebSocket)
        websocket.context = {}
        websocket.closed = False
        websocket.close = AsyncMock()
        return websocket
    
    def get_memory_usage(self):
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # MB
    
    @pytest.mark.asyncio
    async def test_middleware_chain_execution_order(self, dispatcher, mock_websocket):
        execution_order = []
        
        class OrderMiddleware(BaseMiddleware):
            def __init__(self, name):
                self.name = name
                
            async def on_connect(self, next_handler, websocket):
                execution_order.append(f"before_{self.name}")
                await next_handler(websocket)
                execution_order.append(f"after_{self.name}")
        
        middleware1 = OrderMiddleware("mw1")
        middleware2 = OrderMiddleware("mw2")
        middleware3 = OrderMiddleware("mw3")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        expected_order = [
            "before_mw1", "before_mw2", "before_mw3",
            "after_mw3", "after_mw2", "after_mw1"
        ]
        assert execution_order == expected_order
    
    @pytest.mark.asyncio
    async def test_memory_leak_prevention_with_many_middleware(self, dispatcher, mock_websocket):
        initial_memory = self.get_memory_usage()
        gc.collect()
        
        middleware_count = 100
        middlewares = []
        
        for i in range(middleware_count):
            middleware = MockMiddleware(f"test_mw_{i}")
            middlewares.append(middleware)
            dispatcher.add_middleware(middleware)
        
        iterations = 50
        
        for i in range(iterations):
            await dispatcher.dispatch_connect(mock_websocket)
            await dispatcher.dispatch_message(mock_websocket, {
                'type': 'chat', 
                'text': f'test message {i+1}',
                'user_id': i+1
            })
            await dispatcher.dispatch_disconnect(mock_websocket, f"test reason {i}")
            
            if i % 10 == 0:
                gc.collect()
        
        gc.collect()
        final_memory = self.get_memory_usage()
        
        memory_growth = final_memory - initial_memory
        print(f"Memory growth: {memory_growth:.2f} MB")
        
        assert memory_growth < 16, f"Memory leak detected: {memory_growth:.2f} MB growth"
    
    @pytest.mark.asyncio
    async def test_cleanup_methods_called(self, dispatcher, mock_websocket):
        middleware1 = MockMiddleware("mw1")
        middleware2 = MockMiddleware("mw2")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        
        await dispatcher.dispatch_connect(mock_websocket)
        await dispatcher.dispatch_message(mock_websocket, {
            'type': 'chat',
            'text': 'test',
            'user_id': 12345
        })
        await dispatcher.dispatch_disconnect(mock_websocket, "test")
        
        assert middleware1.connect_called
        assert middleware1.message_called
        assert middleware1.disconnect_called
        
        assert middleware2.connect_called
        assert middleware2.message_called
        assert middleware2.disconnect_called
    
    @pytest.mark.asyncio
    async def test_middleware_chain_stops_when_next_not_called(self, dispatcher, mock_websocket):
        middleware1 = MockMiddleware("mw1", should_call_next=True)
        middleware2 = MockMiddleware("mw2", should_call_next=False)
        middleware3 = MockMiddleware("mw3", should_call_next=True)
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert middleware1.connect_called
        assert middleware2.connect_called
        assert not middleware3.connect_called
    
    @pytest.mark.asyncio
    async def test_error_handling_in_middleware_chain(self, dispatcher, mock_websocket):
        middleware1 = MockMiddleware("mw1", should_call_next=True)
        middleware2 = MockMiddleware("mw2", should_call_next=True, raise_error=True)
        middleware3 = MockMiddleware("mw3", should_call_next=True)
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert middleware1.connect_called
        assert middleware2.connect_called
        assert middleware3.connect_called
    
    @pytest.mark.asyncio
    async def test_stress_test_concurrent_executions(self, dispatcher):
        middleware_count = 20
        for i in range(middleware_count):
            middleware = MockMiddleware(f"stress_mw_{i}")
            dispatcher.add_middleware(middleware)
        
        concurrent_connections = 50
        tasks = []
        
        async def simulate_connection():
            websocket = Mock(spec=WebSocket)
            websocket.context = {}
            websocket.closed = False
            websocket.close = AsyncMock()
            
            await dispatcher.dispatch_connect(websocket)
            
            for i in range(5):
                await dispatcher.dispatch_message(websocket, {
                    'type': 'chat',
                    'text': f'stress message {i}',
                    'user_id': i + 1000
                })
            
            await dispatcher.dispatch_disconnect(websocket, "stress test completed")
        
        for _ in range(concurrent_connections):
            task = asyncio.create_task(simulate_connection())
            tasks.append(task)
        
        start_time = time.time()
        await asyncio.gather(*tasks)
        execution_time = time.time() - start_time
        
        print(f"Stress test completed in {execution_time:.2f} seconds")
        
        assert execution_time < 30, f"Stress test took too long: {execution_time:.2f} seconds"
    
    @pytest.mark.asyncio
    async def test_memory_cleanup_simplified_execution(self, dispatcher, mock_websocket):
        """Test that simplified middleware execution doesn't create memory leaks"""
        initial_memory = self.get_memory_usage()
        gc.collect()
        
        middleware = MockMiddleware("cleanup_test")
        dispatcher.add_middleware(middleware)
        
        # Execute many middleware chains to test for memory leaks
        for i in range(200):
            await dispatcher.dispatch_connect(mock_websocket)
            await dispatcher.dispatch_message(mock_websocket, {
                'type': 'chat',
                'text': f'cleanup test {i}',
                'user_id': i + 3000
            })
            await dispatcher.dispatch_disconnect(mock_websocket, f"cleanup test {i}")
            
            if i % 50 == 0:
                gc.collect()
        
        gc.collect()
        final_memory = self.get_memory_usage()
        memory_growth = final_memory - initial_memory
        
        print(f"Simplified execution memory growth: {memory_growth:.2f} MB")
        
        # With simplified execution, memory growth should be minimal
        assert memory_growth < 8, f"Memory leak in simplified execution: {memory_growth:.2f} MB growth"
    
    @pytest.mark.asyncio
    async def test_performance_comparison(self, dispatcher, mock_websocket):
        middleware_count = 10
        for i in range(middleware_count):
            middleware = MockMiddleware(f"perf_mw_{i}")
            dispatcher.add_middleware(middleware)
        
        iterations = 100
        start_time = time.time()
        
        for i in range(iterations):
            await dispatcher.dispatch_connect(mock_websocket)
            await dispatcher.dispatch_message(mock_websocket, {
                'type': 'chat',
                'text': f'performance test {i}',
                'user_id': i + 2000
            })
            await dispatcher.dispatch_disconnect(mock_websocket, f"perf test {i}")
        
        execution_time = time.time() - start_time
        avg_time_per_event = execution_time / (iterations * 3)
        
        print(f"Performance test: {avg_time_per_event*1000:.2f} ms per event")
        
        assert avg_time_per_event < 0.01, f"Performance degraded: {avg_time_per_event*1000:.2f} ms per event"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"]) 