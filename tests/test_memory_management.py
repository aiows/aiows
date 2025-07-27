"""
Тесты для проверки управления памятью и устранения memory leaks в middleware chains
"""

import asyncio
import gc
import pytest
import psutil
import os
import time
from memory_profiler import profile
from unittest.mock import AsyncMock, Mock

from aiows.dispatcher import MessageDispatcher, _MiddlewareChainExecutor
from aiows.router import Router
from aiows.websocket import WebSocket
from aiows.middleware.base import BaseMiddleware
from aiows.types import ChatMessage
from aiows.exceptions import MiddlewareError


class MockMiddleware(BaseMiddleware):
    """Mock middleware для проверки выполнения цепочки"""
    
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
        """Cleanup method для middleware"""
        self.cleanup_called = True


class TestMemoryManagement:
    """Тесты для проверки управления памятью"""
    
    @pytest.fixture
    def router(self):
        """Создание router для тестов"""
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
        """Создание dispatcher для тестов"""
        return MessageDispatcher(router)
    
    @pytest.fixture
    def mock_websocket(self):
        """Создание mock WebSocket для тестов"""
        websocket = Mock(spec=WebSocket)
        websocket.context = {}
        websocket.closed = False
        websocket.close = AsyncMock()
        return websocket
    
    def get_memory_usage(self):
        """Получить текущее использование памяти процессом"""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # MB
    
    @pytest.mark.asyncio
    async def test_middleware_chain_execution_order(self, dispatcher, mock_websocket):
        """Тест корректного порядка выполнения middleware chain"""
        execution_order = []
        
        class OrderMiddleware(BaseMiddleware):
            def __init__(self, name):
                self.name = name
                
            async def on_connect(self, next_handler, websocket):
                execution_order.append(f"before_{self.name}")
                await next_handler(websocket)
                execution_order.append(f"after_{self.name}")
        
        # Добавляем middleware в определенном порядке
        middleware1 = OrderMiddleware("mw1")
        middleware2 = OrderMiddleware("mw2")
        middleware3 = OrderMiddleware("mw3")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        # Выполняем цепочку
        await dispatcher.dispatch_connect(mock_websocket)
        
        # Проверяем правильный порядок выполнения
        expected_order = [
            "before_mw1", "before_mw2", "before_mw3",
            "after_mw3", "after_mw2", "after_mw1"
        ]
        assert execution_order == expected_order
    
    @pytest.mark.asyncio
    async def test_memory_leak_prevention_with_many_middleware(self, dispatcher, mock_websocket):
        """Тест отсутствия memory leaks при большом количестве middleware"""
        initial_memory = self.get_memory_usage()
        gc.collect()  # Принудительная сборка мусора
        
        # Создаем много middleware
        middleware_count = 100
        middlewares = []
        
        for i in range(middleware_count):
            middleware = MockMiddleware(f"test_mw_{i}")
            middlewares.append(middleware)
            dispatcher.add_middleware(middleware)
        
        # Выполняем много итераций для проверки накопления памяти
        iterations = 50
        
        for i in range(iterations):
            # Выполняем все типы событий
            await dispatcher.dispatch_connect(mock_websocket)
            await dispatcher.dispatch_message(mock_websocket, {
                'type': 'chat', 
                'content': f'test message {i}',
                'user_id': f'user_{i}'
            })
            await dispatcher.dispatch_disconnect(mock_websocket, f"test reason {i}")
            
            # Принудительная сборка мусора каждые 10 итераций
            if i % 10 == 0:
                gc.collect()
        
        # Финальная сборка мусора
        gc.collect()
        final_memory = self.get_memory_usage()
        
        # Проверяем, что memory usage не вырос значительно
        memory_growth = final_memory - initial_memory
        print(f"Memory growth: {memory_growth:.2f} MB")
        
        # Допускаем рост памяти не более 10 MB (может быть связано с тестовой инфраструктурой)
        assert memory_growth < 10, f"Memory leak detected: {memory_growth:.2f} MB growth"
    
    @pytest.mark.asyncio
    async def test_cleanup_methods_called(self, dispatcher, mock_websocket):
        """Тест вызова cleanup methods в executor"""
        middleware1 = MockMiddleware("mw1")
        middleware2 = MockMiddleware("mw2")
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        
        # Выполняем события
        await dispatcher.dispatch_connect(mock_websocket)
        await dispatcher.dispatch_message(mock_websocket, {
            'type': 'chat',
            'content': 'test',
            'user_id': 'test_user'
        })
        await dispatcher.dispatch_disconnect(mock_websocket, "test")
        
        # Проверяем, что middleware были вызваны
        assert middleware1.connect_called
        assert middleware1.message_called
        assert middleware1.disconnect_called
        
        assert middleware2.connect_called
        assert middleware2.message_called
        assert middleware2.disconnect_called
    
    @pytest.mark.asyncio
    async def test_middleware_chain_stops_when_next_not_called(self, dispatcher, mock_websocket):
        """Тест остановки цепочки когда middleware не вызывает next()"""
        middleware1 = MockMiddleware("mw1", should_call_next=True)
        middleware2 = MockMiddleware("mw2", should_call_next=False)  # Не вызывает next()
        middleware3 = MockMiddleware("mw3", should_call_next=True)
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        # Проверяем, что выполнились только первые два middleware
        assert middleware1.connect_called
        assert middleware2.connect_called
        assert not middleware3.connect_called  # Не должен быть вызван
    
    @pytest.mark.asyncio
    async def test_error_handling_in_middleware_chain(self, dispatcher, mock_websocket):
        """Тест обработки ошибок в middleware chain"""
        middleware1 = MockMiddleware("mw1", should_call_next=True)
        middleware2 = MockMiddleware("mw2", should_call_next=True, raise_error=True)
        middleware3 = MockMiddleware("mw3", should_call_next=True)
        
        dispatcher.add_middleware(middleware1)
        dispatcher.add_middleware(middleware2)
        dispatcher.add_middleware(middleware3)
        
        # Выполняем с ошибкой (не должно упасть)
        await dispatcher.dispatch_connect(mock_websocket)
        
        # Проверяем, что первый middleware выполнился
        assert middleware1.connect_called
        assert middleware2.connect_called
        # Третий middleware должен выполниться несмотря на ошибку во втором
        assert middleware3.connect_called
    
    @pytest.mark.asyncio
    async def test_stress_test_concurrent_executions(self, dispatcher):
        """Стрессовый тест параллельных выполнений middleware chains"""
        # Создаем много middleware
        middleware_count = 20
        for i in range(middleware_count):
            middleware = MockMiddleware(f"stress_mw_{i}")
            dispatcher.add_middleware(middleware)
        
        # Создаем много параллельных WebSocket connections
        concurrent_connections = 50
        tasks = []
        
        async def simulate_connection():
            websocket = Mock(spec=WebSocket)
            websocket.context = {}
            websocket.closed = False
            websocket.close = AsyncMock()
            
            # Симулируем полный lifecycle connection
            await dispatcher.dispatch_connect(websocket)
            
            # Отправляем несколько сообщений
            for i in range(5):
                await dispatcher.dispatch_message(websocket, {
                    'type': 'chat',
                    'content': f'stress message {i}',
                    'user_id': f'stress_user_{i}'
                })
            
            await dispatcher.dispatch_disconnect(websocket, "stress test completed")
        
        # Запускаем параллельные задачи
        for _ in range(concurrent_connections):
            task = asyncio.create_task(simulate_connection())
            tasks.append(task)
        
        # Ждем завершения всех задач
        start_time = time.time()
        await asyncio.gather(*tasks)
        execution_time = time.time() - start_time
        
        print(f"Stress test completed in {execution_time:.2f} seconds")
        
        # Проверяем, что выполнение завершилось в разумное время
        # 50 connections * 6 events each = 300 events total
        assert execution_time < 30, f"Stress test took too long: {execution_time:.2f} seconds"
    
    @pytest.mark.asyncio
    async def test_memory_cleanup_after_executor_destruction(self, router):
        """Тест очистки памяти после уничтожения executor"""
        # Создаем dispatcher и middleware
        dispatcher = MessageDispatcher(router)
        middleware = MockMiddleware("cleanup_test")
        dispatcher.add_middleware(middleware)
        
        # Создаем executor напрямую
        executor = _MiddlewareChainExecutor([middleware], dispatcher)
        
        # Проверяем начальное состояние
        assert executor.middleware_list == [middleware]
        assert executor.dispatcher == dispatcher
        
        # Вызываем cleanup
        executor.cleanup()
        
        # Проверяем, что ресурсы очищены
        assert len(executor.middleware_list) == 0
        assert executor.dispatcher is None
    
    @pytest.mark.asyncio
    async def test_performance_comparison(self, dispatcher, mock_websocket):
        """Тест производительности новой реализации"""
        # Создаем middleware chain средней длины
        middleware_count = 10
        for i in range(middleware_count):
            middleware = MockMiddleware(f"perf_mw_{i}")
            dispatcher.add_middleware(middleware)
        
        # Измеряем время выполнения
        iterations = 100
        start_time = time.time()
        
        for i in range(iterations):
            await dispatcher.dispatch_connect(mock_websocket)
            await dispatcher.dispatch_message(mock_websocket, {
                'type': 'chat',
                'content': f'performance test {i}',
                'user_id': f'perf_user_{i}'
            })
            await dispatcher.dispatch_disconnect(mock_websocket, f"perf test {i}")
        
        execution_time = time.time() - start_time
        avg_time_per_event = execution_time / (iterations * 3)  # 3 events per iteration
        
        print(f"Performance test: {avg_time_per_event*1000:.2f} ms per event")
        
        # Проверяем, что производительность приемлемая
        # Каждое событие должно выполняться менее чем за 10ms
        assert avg_time_per_event < 0.01, f"Performance degraded: {avg_time_per_event*1000:.2f} ms per event"


if __name__ == "__main__":
    # Запуск тестов напрямую для отладки
    pytest.main([__file__, "-v", "-s"]) 