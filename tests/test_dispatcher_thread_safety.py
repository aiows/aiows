import asyncio
import concurrent.futures
import threading
import time
from unittest.mock import Mock, patch

from aiows.dispatcher import MessageDispatcher
from aiows.router import Router
from aiows.websocket import WebSocket
from aiows.middleware.base import BaseMiddleware


class DemoMiddleware(BaseMiddleware):
    def __init__(self, name: str):
        self.name = name
        self.execution_count = 0
        self.thread_ids = []
        
    async def on_connect(self, next_handler, websocket):
        self.execution_count += 1
        self.thread_ids.append(threading.get_ident())
        await next_handler(websocket)
        
    async def on_message(self, next_handler, websocket, message_data):
        self.execution_count += 1
        self.thread_ids.append(threading.get_ident())
        await next_handler(websocket, message_data)
        
    async def on_disconnect(self, next_handler, websocket, reason):
        self.execution_count += 1
        self.thread_ids.append(threading.get_ident())
        await next_handler(websocket, reason)


class TestDispatcherThreadSafety:

    def test_middleware_execution_without_copying(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        middleware1 = DemoMiddleware("middleware1")
        middleware2 = DemoMiddleware("middleware2")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        
        assert dispatcher._middleware[0] is middleware1
        assert dispatcher._middleware[1] is middleware2
        
        with patch('copy.copy') as mock_copy, \
             patch('copy.deepcopy') as mock_deepcopy:
            
            mock_websocket = Mock(spec=WebSocket)
            mock_websocket.remote_address = "127.0.0.1:1234"
            mock_websocket.closed = False
            mock_websocket.context = {}
            
            asyncio.run(dispatcher.dispatch_connect(mock_websocket))
            
            mock_copy.assert_not_called()
            mock_deepcopy.assert_not_called()
            
        assert middleware1.execution_count == 1
        assert middleware2.execution_count == 1

    def test_remove_middleware_functionality(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        middleware1 = DemoMiddleware("middleware1")
        middleware2 = DemoMiddleware("middleware2")
        middleware3 = DemoMiddleware("middleware3")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        assert len(dispatcher._middleware) == 3
        assert middleware2 in dispatcher._middleware
        
        result = dispatcher.remove_middleware(middleware2)
        assert result is True
        assert len(dispatcher._middleware) == 2
        assert middleware2 not in dispatcher._middleware
        assert middleware1 in dispatcher._middleware
        assert middleware3 in dispatcher._middleware
        
        result = dispatcher.remove_middleware(middleware2)
        assert result is False
        assert len(dispatcher._middleware) == 2

    def test_runtime_middleware_modification_thread_safety(self):
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        middleware1 = DemoMiddleware("middleware1")
        middleware2 = DemoMiddleware("middleware2")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        
        mock_websocket = Mock(spec=WebSocket)
        mock_websocket.remote_address = "127.0.0.1:1234"
        mock_websocket.closed = False
        mock_websocket.context = {}
        
        async def execute_dispatch():
            await dispatcher.dispatch_connect(mock_websocket)
        
        def modify_middleware():
            time.sleep(0.001)
            new_middleware = DemoMiddleware("new_middleware")
            dispatcher.add_middleware(new_middleware)
            dispatcher.remove_middleware(middleware1)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future1 = executor.submit(lambda: asyncio.run(execute_dispatch()))
            future2 = executor.submit(modify_middleware)
            
            future1.result()
            future2.result()
        
        total_executions = middleware1.execution_count + middleware2.execution_count
        assert total_executions > 0 

    def test_performance_improvement_without_copying(self):
        import timeit
        
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        for i in range(5):
            middleware = DemoMiddleware(f"middleware_{i}")
            dispatcher.add_middleware(middleware)
        
        mock_websocket = Mock(spec=WebSocket)
        mock_websocket.remote_address = "127.0.0.1:1234"
        mock_websocket.closed = False
        mock_websocket.context = {}
        
        def test_dispatch():
            asyncio.run(dispatcher.dispatch_connect(mock_websocket))
        
        for _ in range(10):
            test_dispatch()
        
        time_without_copying = timeit.timeit(test_dispatch, number=100)
        
        print(f"\nBenchmark results:")
        print(f"Execution time without copying (100 iterations): {time_without_copying:.4f} sec")
        print(f"Average time per iteration: {time_without_copying/100*1000:.2f} ms")
        
        for i in range(5):
            assert dispatcher._middleware[i].execution_count >= 100
        
        assert time_without_copying < 0.050, f"Performance too slow: {time_without_copying:.4f}s"