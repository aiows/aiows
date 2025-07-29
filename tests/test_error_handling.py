"""
Tests for improved error handling in websocket.py and dispatcher.py
"""

import asyncio
import socket
import ssl
import pytest
from unittest.mock import Mock, AsyncMock, patch
from aiows.websocket import WebSocket, error_metrics, ErrorMetrics
from aiows.dispatcher import MessageDispatcher, dispatcher_error_metrics, DispatcherErrorMetrics
from aiows.router import Router
from aiows.exceptions import (
    ConnectionError, MessageValidationError, MiddlewareError, 
    MessageSizeError, ErrorCategory, ErrorContext, ErrorCategorizer
)
from aiows.middleware.base import BaseMiddleware


class TestErrorCategorization:
    """Test the new error categorization system"""
    
    def test_categorize_fatal_errors(self):
        """Test that FATAL errors are correctly categorized"""
        memory_error = MemoryError("Out of memory")
        os_error = OSError("System resource error")
        
        assert ErrorCategorizer.categorize_exception(memory_error) == ErrorCategory.FATAL
        assert ErrorCategorizer.categorize_exception(os_error) == ErrorCategory.FATAL
    
    def test_categorize_client_errors(self):
        """Test that CLIENT_ERROR exceptions are correctly categorized"""
        validation_error = MessageValidationError("Invalid message format")
        size_error = MessageSizeError("Message too large")
        
        assert ErrorCategorizer.categorize_exception(validation_error) == ErrorCategory.CLIENT_ERROR
        assert ErrorCategorizer.categorize_exception(size_error) == ErrorCategory.CLIENT_ERROR
    
    def test_categorize_server_errors(self):
        """Test that SERVER_ERROR exceptions are correctly categorized"""
        middleware_error = MiddlewareError("Middleware failed")
        connection_error = ConnectionError("Connection lost")
        
        assert ErrorCategorizer.categorize_exception(middleware_error) == ErrorCategory.SERVER_ERROR
        assert ErrorCategorizer.categorize_exception(connection_error) == ErrorCategory.SERVER_ERROR
    
    def test_categorize_recoverable_errors(self):
        """Test that RECOVERABLE errors are correctly categorized"""
        timeout_error = TimeoutError("Operation timed out")
        asyncio_timeout = asyncio.TimeoutError("Async timeout")
        
        assert ErrorCategorizer.categorize_exception(timeout_error) == ErrorCategory.RECOVERABLE
        assert ErrorCategorizer.categorize_exception(asyncio_timeout) == ErrorCategory.RECOVERABLE
    
    def test_categorize_unknown_errors_as_server_error(self):
        """Test that unknown exceptions default to SERVER_ERROR"""
        unknown_error = ValueError("Unknown validation error")
        
        assert ErrorCategorizer.categorize_exception(unknown_error) == ErrorCategory.SERVER_ERROR
    
    def test_middleware_chain_stopping_logic(self):
        """Test the logic for stopping middleware chains"""
        memory_error = MemoryError("Out of memory")
        assert ErrorCategorizer.should_stop_middleware_chain(memory_error) == True
        
        connection_error = ConnectionError("Connection lost")
        assert ErrorCategorizer.should_stop_middleware_chain(connection_error) == True
        
        middleware_error = MiddlewareError("Auth failed")
        assert ErrorCategorizer.should_stop_middleware_chain(middleware_error, "AuthMiddleware") == True
        
        validation_error = MessageValidationError("Invalid message")
        assert ErrorCategorizer.should_stop_middleware_chain(validation_error) == True
        
        regular_error = MiddlewareError("Regular middleware error")
        assert ErrorCategorizer.should_stop_middleware_chain(regular_error, "LoggingMiddleware") == False
    
    def test_log_level_assignment(self):
        """Test that appropriate log levels are assigned to error categories"""
        memory_error = MemoryError("Out of memory")
        assert ErrorCategorizer.get_log_level(memory_error) == 'critical'
        
        middleware_error = MiddlewareError("Middleware failed")
        assert ErrorCategorizer.get_log_level(middleware_error) == 'error'
        
        validation_error = MessageValidationError("Invalid message")
        assert ErrorCategorizer.get_log_level(validation_error) == 'warning'
        
        timeout_error = TimeoutError("Operation timed out")
        assert ErrorCategorizer.get_log_level(timeout_error) == 'info'


class TestErrorContext:
    """Test the ErrorContext class"""
    
    def test_error_context_creation(self):
        """Test ErrorContext creation and methods"""
        context = ErrorContext(
            operation="test_operation",
            component="test_component",
            additional_context={"key": "value"}
        )
        
        assert context.operation == "test_operation"
        assert context.component == "test_component"
        assert context.additional_context["key"] == "value"
        assert context.error_id is not None
        assert len(context.error_id) == 8
        
        context_dict = context.to_dict()
        assert context_dict["operation"] == "test_operation"
        assert context_dict["component"] == "test_component"
        assert context_dict["key"] == "value"
        assert context_dict["error_id"] == context.error_id
    
    def test_error_context_with_custom_id(self):
        """Test ErrorContext with custom error ID"""
        custom_id = "TEST123"
        context = ErrorContext(
            operation="test_operation",
            component="test_component",
            error_id=custom_id
        )
        
        assert context.error_id == custom_id


class TestWebSocketErrorHandling:
    """Test improved error handling in WebSocket class"""
    
    @pytest.fixture
    def mock_websocket(self):
        ws = Mock()
        ws.remote_address = ('127.0.0.1', 8080)
        return ws
    
    @pytest.fixture
    def websocket_wrapper(self, mock_websocket):
        return WebSocket(mock_websocket)
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        yield
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
    
    @pytest.mark.asyncio
    async def test_timeout_error_handling(self, websocket_wrapper):
        websocket_wrapper._websocket.send = AsyncMock(side_effect=asyncio.TimeoutError())
        
        with pytest.raises(ConnectionError, match="Send operation timed out"):
            await websocket_wrapper.send("test")
        
        assert websocket_wrapper.closed
        assert error_metrics.timeout_errors == 1
        assert error_metrics.recoverable_errors == 1
        assert websocket_wrapper._error_count == 1
    
    @pytest.mark.asyncio
    async def test_cancellation_not_masked(self, websocket_wrapper):
        websocket_wrapper._websocket.send = AsyncMock(side_effect=asyncio.CancelledError())
        
        with pytest.raises(asyncio.CancelledError):
            await websocket_wrapper.send("test")
        
        assert websocket_wrapper.closed
    
    @pytest.mark.asyncio
    async def test_json_serialization_error_handling(self, websocket_wrapper):
        unserializable = object()
        
        with pytest.raises(ConnectionError, match="JSON serialization failed"):
            await websocket_wrapper.send_json({"data": unserializable})
        
        assert error_metrics.json_errors == 1
        assert error_metrics.server_errors == 1
        assert not websocket_wrapper.closed
    
    @pytest.mark.asyncio
    async def test_network_error_handling(self, websocket_wrapper):
        websocket_wrapper._websocket.send = AsyncMock(side_effect=socket.error("Network unreachable"))
        
        with pytest.raises(ConnectionError, match="Network error during send"):
            await websocket_wrapper.send("test")
        
        assert error_metrics.network_errors == 1
        assert error_metrics.fatal_errors == 1
        assert websocket_wrapper.closed
    
    @pytest.mark.asyncio
    async def test_ssl_error_handling(self, websocket_wrapper):
        websocket_wrapper._websocket.recv = AsyncMock(side_effect=ssl.SSLError("SSL handshake failed"))
        
        with pytest.raises(ConnectionError, match="SSL error during receive"):
            await websocket_wrapper.recv()
        
        assert error_metrics.ssl_errors == 1
        assert error_metrics.fatal_errors == 1
        assert websocket_wrapper.closed

    @pytest.mark.asyncio
    async def test_message_size_error_recoverable(self, websocket_wrapper):
        large_message = "x" * (websocket_wrapper._max_message_size + 1)
        websocket_wrapper._websocket.recv = AsyncMock(return_value=large_message)
        
        with pytest.raises(MessageSizeError):
            await websocket_wrapper.recv()
        
        assert error_metrics.size_errors == 1
        assert error_metrics.client_errors == 1
        assert not websocket_wrapper.closed
    
    @pytest.mark.asyncio
    async def test_json_decode_error_handling(self, websocket_wrapper):
        websocket_wrapper._websocket.recv = AsyncMock(return_value="invalid json {")
        
        with pytest.raises(ConnectionError, match="Invalid JSON received"):
            await websocket_wrapper.receive_json()
        
        assert error_metrics.json_errors == 1
    
    @pytest.mark.asyncio
    async def test_unexpected_error_not_masked(self, websocket_wrapper):
        class UnexpectedError(Exception):
            pass
        
        websocket_wrapper._websocket.send = AsyncMock(side_effect=UnexpectedError("Something unexpected"))
        
        with pytest.raises(ConnectionError, match="Unexpected error during send"):
            await websocket_wrapper.send("test")
        
        assert error_metrics.unexpected_errors == 1
        assert error_metrics.server_errors == 1
        assert websocket_wrapper.closed
    
    @pytest.mark.asyncio
    async def test_error_recovery_mechanism(self, websocket_wrapper):
        websocket_wrapper._websocket.send = AsyncMock(side_effect=socket.error("Network error"))
        with pytest.raises(ConnectionError):
            await websocket_wrapper.send("test1")
        
        assert websocket_wrapper._error_count == 1
        assert websocket_wrapper.closed
        
        websocket_wrapper._reset_connection_state_for_testing()
        
        websocket_wrapper._websocket.send = AsyncMock()
        await websocket_wrapper.send("test2")
        
        assert websocket_wrapper._error_count == 0
    
    @pytest.mark.asyncio
    async def test_graceful_close_error_handling(self, websocket_wrapper):
        websocket_wrapper._websocket.close = AsyncMock(side_effect=socket.error("Connection already closed"))
        
        await websocket_wrapper.close()
        assert websocket_wrapper.closed
    
    def test_remote_address_error_handling(self, websocket_wrapper):
        del websocket_wrapper._websocket.remote_address
        
        addr = websocket_wrapper.remote_address
        assert addr == ('unknown', 0)
    
    @pytest.mark.asyncio
    async def test_error_context_logging(self, websocket_wrapper):
        with patch('aiows.websocket.logger') as mock_logger:
            websocket_wrapper._websocket.send = AsyncMock(side_effect=socket.error("Test error"))
            
            with pytest.raises(ConnectionError):
                await websocket_wrapper.send("test")
            
            assert mock_logger.error.call_count > 0 or mock_logger.critical.call_count > 0


class TestDispatcherErrorHandling:
    """Test improved error handling in MessageDispatcher class"""
    
    @pytest.fixture
    def router(self):
        return Router()
    
    @pytest.fixture
    def dispatcher(self, router):
        return MessageDispatcher(router)
    
    @pytest.fixture
    def mock_websocket(self):
        ws = Mock()
        ws.context = {}
        ws.remote_address = ('127.0.0.1', 8080)
        ws.closed = False
        ws.close = AsyncMock()
        return ws
    
    @pytest.fixture(autouse=True)
    def reset_dispatcher_metrics(self):
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        dispatcher_error_metrics.last_error_time = 0
        yield
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        dispatcher_error_metrics.last_error_time = 0
    
    def test_message_parsing_specific_errors(self, dispatcher):
        with pytest.raises(MessageValidationError, match="Failed to parse message"):
            dispatcher._parse_message_safely({"invalid": "data"})
        
        assert dispatcher_error_metrics.parsing_errors == 1
        assert dispatcher_error_metrics.client_errors == 1
    
    def test_message_parsing_recursion_error(self, dispatcher):
        deep_data = {"type": "chat", "text": "test", "user_id": "user1"}
        current = deep_data
        for i in range(1000):
            current["nested"] = {}
            current = current["nested"]
        
        with patch('aiows.types.ChatMessage.__init__', side_effect=RecursionError("Maximum recursion depth")):
            with pytest.raises(MessageValidationError, match="Message structure too complex"):
                dispatcher._parse_message_safely(deep_data)
        
        assert dispatcher_error_metrics.parsing_errors == 1
        assert dispatcher_error_metrics.client_errors == 1
    
    def test_message_parsing_memory_error(self, dispatcher):
        with patch('aiows.types.ChatMessage.__init__', side_effect=MemoryError("Out of memory")):
            with pytest.raises(MemoryError):
                dispatcher._parse_message_safely({"type": "chat", "text": "test", "user_id": "user1"})
        
        assert dispatcher_error_metrics.critical_errors == 1
        assert dispatcher_error_metrics.fatal_errors == 1
    
    def test_message_parsing_unexpected_error_not_masked(self, dispatcher):
        class UnexpectedError(Exception):
            pass
        
        with patch('aiows.types.ChatMessage.__init__', side_effect=UnexpectedError("Something unexpected")):
            with pytest.raises(MessageValidationError, match="Unexpected parsing error"):
                dispatcher._parse_message_safely({"type": "chat", "text": "test", "user_id": "user1"})
        
        assert dispatcher_error_metrics.unexpected_errors == 1
        assert dispatcher_error_metrics.server_errors == 1
    
    @pytest.mark.asyncio
    async def test_middleware_exception_handling(self, dispatcher, mock_websocket):
        class TestMiddleware(BaseMiddleware):
            async def on_connect(self, call_next, websocket):
                raise MiddlewareError("Test middleware error")
        
        middleware = TestMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            MiddlewareError("Test error"), middleware, "connect", mock_websocket
        )
        
        assert should_continue
        assert dispatcher_error_metrics.server_errors == 1
        assert dispatcher._consecutive_errors == 1
    
    @pytest.mark.asyncio
    async def test_critical_middleware_exception_handling(self, dispatcher, mock_websocket):
        class AuthMiddleware(BaseMiddleware):
            async def on_connect(self, call_next, websocket):
                raise MiddlewareError("Auth failed")
        
        middleware = AuthMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            MiddlewareError("Auth failed"), middleware, "connect", mock_websocket
        )
        
        assert not should_continue
    
    @pytest.mark.asyncio
    async def test_connection_error_middleware_handling(self, dispatcher, mock_websocket):
        class TestMiddleware(BaseMiddleware):
            pass
        
        middleware = TestMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            ConnectionError("Connection lost"), middleware, "connect", mock_websocket
        )
        
        assert not should_continue
        assert dispatcher_error_metrics.server_errors == 1
    
    @pytest.mark.asyncio
    async def test_timeout_error_middleware_handling(self, dispatcher, mock_websocket):
        class TestMiddleware(BaseMiddleware):
            pass
        
        middleware = TestMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            asyncio.TimeoutError("Operation timed out"), middleware, "connect", mock_websocket
        )
        
        assert not should_continue
        assert dispatcher_error_metrics.recoverable_errors == 1
    
    @pytest.mark.asyncio
    async def test_memory_error_middleware_handling(self, dispatcher, mock_websocket):
        class TestMiddleware(BaseMiddleware):
            pass
        
        middleware = TestMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            MemoryError("Out of memory"), middleware, "connect", mock_websocket
        )
        
        assert not should_continue
        assert dispatcher_error_metrics.critical_errors == 1
        assert dispatcher_error_metrics.fatal_errors == 1
    
    @pytest.mark.asyncio
    async def test_unexpected_middleware_error_not_masked(self, dispatcher, mock_websocket):
        class UnexpectedError(Exception):
            pass
        
        class TestMiddleware(BaseMiddleware):
            pass
        
        middleware = TestMiddleware()
        
        should_continue = await dispatcher._handle_middleware_exception(
            UnexpectedError("Something unexpected"), middleware, "connect", mock_websocket
        )
        
        assert should_continue
        assert dispatcher_error_metrics.server_errors == 1
    
    @pytest.mark.asyncio
    async def test_handler_error_recovery(self, dispatcher, router, mock_websocket):
        @router.connect()
        async def failing_handler(websocket):
            raise ValueError("Handler error")
        
        @router.connect()
        async def working_handler(websocket):
            websocket.handler_called = True
        
        await dispatcher._execute_connect_chain(mock_websocket)
        
        assert hasattr(mock_websocket, 'handler_called')
        assert dispatcher_error_metrics.unexpected_errors == 1
        assert dispatcher_error_metrics.server_errors == 1
    
    @pytest.mark.asyncio
    async def test_handler_critical_error_propagation(self, dispatcher, router, mock_websocket):
        @router.connect()
        async def critical_handler(websocket):
            raise MemoryError("Critical error")
        
        with pytest.raises(MemoryError):
            await dispatcher._execute_connect_chain(mock_websocket)
        
        assert dispatcher_error_metrics.critical_errors == 1
        assert dispatcher_error_metrics.fatal_errors == 1
    
    @pytest.mark.asyncio
    async def test_handler_async_error_propagation(self, dispatcher, router, mock_websocket):
        @router.connect()
        async def timeout_handler(websocket):
            raise asyncio.TimeoutError("Timeout in handler")
        
        with pytest.raises(asyncio.TimeoutError):
            await dispatcher._execute_connect_chain(mock_websocket)
        
        assert dispatcher_error_metrics.timeout_errors == 1
        assert dispatcher_error_metrics.recoverable_errors == 1
    
    @pytest.mark.asyncio
    async def test_consecutive_error_tracking(self, dispatcher, router, mock_websocket):
        call_count = 0
        
        @router.connect()
        async def sometimes_failing_handler(websocket):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ValueError("Temporary error")
        
        await dispatcher._execute_connect_chain(mock_websocket)
        assert dispatcher._consecutive_errors == 1
        
        await dispatcher._execute_connect_chain(mock_websocket)
        assert dispatcher._consecutive_errors == 2
        
        await dispatcher._execute_connect_chain(mock_websocket)
        assert dispatcher._consecutive_errors == 1
    
    @pytest.mark.asyncio
    async def test_enhanced_error_context_logging(self, dispatcher, mock_websocket):
        class TestMiddleware(BaseMiddleware):
            pass
        
        middleware = TestMiddleware()
        
        with patch.object(dispatcher, '_log_error_with_context') as mock_log:
            should_continue = await dispatcher._handle_middleware_exception(
                ValueError("Test error"), middleware, "connect", mock_websocket
            )
            
            assert should_continue
            
            mock_log.assert_called()
            call_args = mock_log.call_args[0]
            assert isinstance(call_args[0], ValueError)
            assert hasattr(call_args[1], 'operation')
            assert hasattr(call_args[1], 'error_id')
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_preserved(self, dispatcher, router, mock_websocket):
        @router.message()
        async def handler1(websocket, message):
            raise MessageValidationError("Validation failed")
        
        @router.message()
        async def handler2(websocket, message):
            websocket.second_handler_called = True
        
        message_data = {"type": "chat", "text": "test", "user_id": 1}
        await dispatcher._execute_message_chain(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.handler_errors == 1
        assert dispatcher_error_metrics.client_errors == 1


class TestErrorMetrics:
    """Test error metrics functionality"""
    
    def test_error_metrics_increment(self):
        metrics = ErrorMetrics()
        
        metrics.increment('timeout')
        assert metrics.timeout_errors == 1
        
        metrics.increment('connection')
        assert metrics.connection_errors == 1
        
        metrics.increment('nonexistent')
        assert not hasattr(metrics, 'nonexistent_errors')
    
    def test_error_metrics_categorized_increment(self):
        """Test the new categorized metrics"""
        metrics = ErrorMetrics()
        
        metrics.increment_category(ErrorCategory.FATAL)
        assert metrics.fatal_errors == 1
        
        metrics.increment_category(ErrorCategory.CLIENT_ERROR)
        assert metrics.client_errors == 1
        
        metrics.increment_category(ErrorCategory.SERVER_ERROR)
        assert metrics.server_errors == 1
        
        metrics.increment_category(ErrorCategory.RECOVERABLE)
        assert metrics.recoverable_errors == 1
    
    def test_dispatcher_error_metrics_increment(self):
        metrics = DispatcherErrorMetrics()
        
        metrics.increment('middleware')
        assert metrics.middleware_errors == 1
        assert metrics.last_error_time > 0
        
        metrics.increment('parsing')
        assert metrics.parsing_errors == 1
    
    def test_dispatcher_error_metrics_categorized_increment(self):
        """Test the new categorized metrics for dispatcher"""
        metrics = DispatcherErrorMetrics()
        
        metrics.increment_category(ErrorCategory.FATAL)
        assert metrics.fatal_errors == 1
        
        metrics.increment_category(ErrorCategory.CLIENT_ERROR)
        assert metrics.client_errors == 1
        
        metrics.increment_category(ErrorCategory.SERVER_ERROR)
        assert metrics.server_errors == 1
        
        metrics.increment_category(ErrorCategory.RECOVERABLE)
        assert metrics.recoverable_errors == 1


class TestErrorHandlingIntegration:
    """Integration tests for error handling across components"""
    
    @pytest.fixture
    def router(self):
        return Router()
    
    @pytest.fixture
    def dispatcher(self, router):
        return MessageDispatcher(router)
    
    @pytest.fixture
    def mock_websocket(self):
        ws = Mock()
        ws.context = {}
        ws.remote_address = ('127.0.0.1', 8080)
        ws.closed = False
        ws.close = AsyncMock()
        return ws
    
    @pytest.mark.asyncio
    async def test_end_to_end_error_recovery(self, dispatcher, router, mock_websocket):
        class SometimesFailingMiddleware(BaseMiddleware):
            def __init__(self):
                self.call_count = 0
            
            async def on_message(self, call_next, websocket, message_data):
                self.call_count += 1
                if self.call_count == 1:
                    raise ConnectionError("Temporary connection issue")
                await call_next(websocket, message_data)
        
        middleware = SometimesFailingMiddleware()
        dispatcher.add_middleware(middleware)
        
        @router.message()
        async def message_handler(websocket, message):
            websocket.message_processed = True
        
        message_data = {"type": "chat", "text": "test1", "user_id": 1}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.server_errors == 1
        
        message_data = {"type": "chat", "text": "test2", "user_id": 1}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert hasattr(mock_websocket, 'message_processed')
    
    @pytest.mark.asyncio
    async def test_critical_error_propagation(self, dispatcher, router, mock_websocket):
        class CriticalFailingMiddleware(BaseMiddleware):
            async def on_connect(self, call_next, websocket):
                raise MemoryError("Critical system error")
        
        dispatcher.add_middleware(CriticalFailingMiddleware())
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert dispatcher_error_metrics.critical_errors == 1
        assert dispatcher_error_metrics.fatal_errors == 1
    
    @pytest.mark.asyncio 
    async def test_error_category_consistency_across_components(self, dispatcher, router):
        """Test that error categories are consistent between WebSocket and Dispatcher"""
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        
        validation_error = MessageValidationError("Invalid format")
        
        websocket_category = ErrorCategorizer.categorize_exception(validation_error)
        
        dispatcher_category = ErrorCategorizer.categorize_exception(validation_error)
        
        assert websocket_category == dispatcher_category == ErrorCategory.CLIENT_ERROR 