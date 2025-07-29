"""
Tests for error categories and their behavior across the framework
"""

import asyncio
import socket
import ssl
import pytest
from unittest.mock import Mock, AsyncMock, patch
from aiows.websocket import WebSocket, error_metrics
from aiows.dispatcher import MessageDispatcher, dispatcher_error_metrics
from aiows.router import Router
from aiows.exceptions import (
    ConnectionError, MessageValidationError, MiddlewareError, 
    MessageSizeError, ErrorCategory, ErrorContext, ErrorCategorizer
)
from aiows.middleware.base import BaseMiddleware


class TestFatalErrorHandling:
    """Test FATAL error category behavior"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_memory_error_stops_everything(self):
        """Test that MemoryError stops all processing"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class FatalMiddleware(BaseMiddleware):
            async def on_connect(self, call_next, websocket):
                raise MemoryError("System out of memory")
        
        dispatcher.add_middleware(FatalMiddleware())
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert dispatcher_error_metrics.fatal_errors == 1
        assert dispatcher_error_metrics.critical_errors == 1
    
    @pytest.mark.asyncio
    async def test_os_error_stops_everything(self):
        """Test that OSError stops all processing"""
        ws = Mock()
        ws.remote_address = ('127.0.0.1', 8080)
        websocket = WebSocket(ws)
        
        ws.send = AsyncMock(side_effect=OSError("System resource unavailable"))
        
        with pytest.raises(ConnectionError):
            await websocket.send("test")
        
        assert websocket.closed
        assert error_metrics.fatal_errors == 1
        assert error_metrics.network_errors == 1
    
    @pytest.mark.asyncio
    async def test_fatal_errors_use_critical_logging(self):
        """Test that FATAL errors use critical log level"""
        memory_error = MemoryError("Critical system failure")
        log_level = ErrorCategorizer.get_log_level(memory_error)
        
        assert log_level == 'critical'
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(memory_error)
        assert should_stop == True


class TestRecoverableErrorHandling:
    """Test RECOVERABLE error category behavior"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_timeout_errors_allow_retry(self):
        """Test that timeout errors can be recovered from"""
        ws = Mock()
        ws.remote_address = ('127.0.0.1', 8080)
        websocket = WebSocket(ws)
        
        ws.send = AsyncMock(side_effect=asyncio.TimeoutError("Operation timed out"))
        
        with pytest.raises(ConnectionError):
            await websocket.send("test1")
        
        assert websocket.closed
        assert error_metrics.recoverable_errors == 1
        assert error_metrics.timeout_errors == 1
        
        websocket._reset_connection_state_for_testing()
        
        ws.send = AsyncMock()
        await websocket.send("test2")
        
        assert websocket._error_count == 0
    
    @pytest.mark.asyncio
    async def test_recoverable_errors_use_info_logging(self):
        """Test that RECOVERABLE errors use info log level"""
        timeout_error = asyncio.TimeoutError("Operation timed out")
        log_level = ErrorCategorizer.get_log_level(timeout_error)
        
        assert log_level == 'info'
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(timeout_error)
        assert should_stop == True
    
    @pytest.mark.asyncio
    async def test_graceful_degradation_with_timeout(self):
        """Test graceful degradation when middleware times out"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        call_count = 0
        
        class TimeoutMiddleware(BaseMiddleware):
            async def on_message(self, call_next, websocket, message_data):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise asyncio.TimeoutError("Middleware timeout")
                await call_next(websocket, message_data)
        
        dispatcher.add_middleware(TimeoutMiddleware())
        
        @router.message()
        async def message_handler(websocket, message):
            websocket.message_processed = True
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        message_data = {"type": "chat", "text": "test1", "user_id": 1}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.recoverable_errors == 1
        
        message_data = {"type": "chat", "text": "test2", "user_id": 1}  
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert hasattr(mock_websocket, 'message_processed')


class TestClientErrorHandling:
    """Test CLIENT_ERROR category behavior"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_message_validation_errors_stop_chain_but_preserve_connection(self):
        """Test that validation errors stop middleware chain but don't close connection unnecessarily"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        with pytest.raises(MessageValidationError):
            dispatcher._parse_message_safely({"invalid": "message_structure"})
        
        assert dispatcher_error_metrics.client_errors == 1
        assert dispatcher_error_metrics.parsing_errors == 1
    
    @pytest.mark.asyncio
    async def test_message_size_errors_are_client_errors(self):
        """Test that oversized messages are treated as client errors"""
        ws = Mock()
        ws.remote_address = ('127.0.0.1', 8080)
        websocket = WebSocket(ws, max_message_size=100)
        
        large_message = "x" * 150
        ws.recv = AsyncMock(return_value=large_message)
        
        with pytest.raises(MessageSizeError):
            await websocket.recv()
        
        assert error_metrics.client_errors == 1
        assert error_metrics.size_errors == 1
        assert not websocket.closed
    
    @pytest.mark.asyncio
    async def test_client_errors_use_warning_logging(self):
        """Test that CLIENT errors use warning log level"""
        validation_error = MessageValidationError("Invalid message format")
        log_level = ErrorCategorizer.get_log_level(validation_error)
        
        assert log_level == 'warning'
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(validation_error)
        assert should_stop == True
    
    @pytest.mark.asyncio
    async def test_client_error_response_to_client(self):
        """Test that client errors result in appropriate responses to client"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class ValidationMiddleware(BaseMiddleware):
            async def on_message(self, call_next, websocket, message_data):
                if not message_data.get("user_id"):
                    raise MessageValidationError("Missing user_id")
                await call_next(websocket, message_data)
        
        dispatcher.add_middleware(ValidationMiddleware())
        
        handler_called = False
        
        @router.message()
        async def message_handler(websocket, message):
            nonlocal handler_called
            handler_called = True
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        message_data = {"type": "chat", "text": "test"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.client_errors == 1
        assert not handler_called


class TestServerErrorHandling:
    """Test SERVER_ERROR category behavior"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_middleware_errors_allow_graceful_degradation(self):
        """Test that middleware errors allow graceful degradation"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class FailingMiddleware(BaseMiddleware):
            async def on_message(self, call_next, websocket, message_data):
                raise MiddlewareError("Internal middleware failure")
        
        class WorkingMiddleware(BaseMiddleware):
            async def on_message(self, call_next, websocket, message_data):
                websocket.working_middleware_called = True
                await call_next(websocket, message_data)
        
        dispatcher.add_middleware(FailingMiddleware())
        dispatcher.add_middleware(WorkingMiddleware())
        
        @router.message()
        async def message_handler(websocket, message):
            websocket.handler_called = True
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        message_data = {"type": "chat", "text": "test", "user_id": 1}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.server_errors == 1
        assert hasattr(mock_websocket, 'working_middleware_called')
        assert hasattr(mock_websocket, 'handler_called')
    
    @pytest.mark.asyncio
    async def test_connection_errors_stop_processing(self):
        """Test that connection errors stop processing"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class ConnectionFailingMiddleware(BaseMiddleware):
            async def on_connect(self, call_next, websocket):
                raise ConnectionError("Connection establishment failed")
        
        dispatcher.add_middleware(ConnectionFailingMiddleware())
        
        connect_handler_called = False
        
        @router.connect()
        async def connect_handler(websocket):
            nonlocal connect_handler_called
            connect_handler_called = True
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        await dispatcher.dispatch_connect(mock_websocket)
        
        assert dispatcher_error_metrics.server_errors == 1
        assert not connect_handler_called
    
    @pytest.mark.asyncio
    async def test_server_errors_use_error_logging(self):
        """Test that SERVER errors use error log level"""
        middleware_error = MiddlewareError("Internal server error")
        log_level = ErrorCategorizer.get_log_level(middleware_error)
        
        assert log_level == 'error'
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(middleware_error, "RegularMiddleware")
        assert should_stop == False
    
    @pytest.mark.asyncio
    async def test_critical_middleware_errors_stop_chain(self):
        """Test that auth/security middleware errors stop the chain"""
        auth_error = MiddlewareError("Authentication failed")
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(auth_error, "AuthMiddleware")
        assert should_stop == True
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(auth_error, "SecurityMiddleware")
        assert should_stop == True
        
        should_stop = ErrorCategorizer.should_stop_middleware_chain(auth_error, "LoggingMiddleware")
        assert should_stop == False


class TestErrorContextPreservation:
    """Test that error context is preserved through the call chain"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_websocket_error_context_preservation(self):
        """Test that WebSocket errors preserve context through the chain"""
        ws = Mock()
        ws.remote_address = ('127.0.0.1', 8080)
        websocket = WebSocket(ws)
        
        ws.send = AsyncMock(side_effect=socket.error("Network failure"))
        
        with patch.object(websocket, '_log_error_with_context') as mock_log:
            with pytest.raises(ConnectionError):
                await websocket.send("test")
            
            mock_log.assert_called()
            error_arg, context_arg = mock_log.call_args[0]
            
            assert isinstance(error_arg, socket.error)
            assert hasattr(context_arg, 'operation')
            assert hasattr(context_arg, 'component')
            assert hasattr(context_arg, 'error_id')
            assert context_arg.operation == 'send'
            assert context_arg.component == 'websocket'
    
    @pytest.mark.asyncio
    async def test_dispatcher_error_context_preservation(self):
        """Test that Dispatcher errors preserve context through the chain"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class ContextTestMiddleware(BaseMiddleware):
            async def on_message(self, call_next, websocket, message_data):
                raise ValueError("Test error with context")
        
        dispatcher.add_middleware(ContextTestMiddleware())
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        with patch.object(dispatcher, '_log_error_with_context') as mock_log:
            message_data = {"type": "chat", "text": "test", "user_id": 1}
            await dispatcher.dispatch_message(mock_websocket, message_data)
            
            mock_log.assert_called()
            error_arg, context_arg = mock_log.call_args[0]
            
            assert isinstance(error_arg, ValueError)
            assert hasattr(context_arg, 'operation')
            assert hasattr(context_arg, 'component')
            assert hasattr(context_arg, 'error_id')
            assert 'middleware_message' in context_arg.operation
            assert context_arg.component == 'dispatcher'
            assert 'middleware_name' in context_arg.additional_context
    
    @pytest.mark.asyncio
    async def test_error_id_consistency(self):
        """Test that error IDs are consistent and unique"""
        context1 = ErrorContext(operation="test1", component="test")
        context2 = ErrorContext(operation="test2", component="test")
        
        assert context1.error_id != context2.error_id
        
        assert context1.error_id == context1.error_id
        
        custom_context = ErrorContext(operation="test", component="test", error_id="CUSTOM123")
        assert custom_context.error_id == "CUSTOM123"


class TestIntegrationErrorHandling:
    """Integration tests for error handling across all components"""
    
    @pytest.fixture(autouse=True)
    def reset_metrics(self):
        for attr in dir(error_metrics):
            if attr.endswith('_errors'):
                setattr(error_metrics, attr, 0)
        for attr in dir(dispatcher_error_metrics):
            if attr.endswith('_errors'):
                setattr(dispatcher_error_metrics, attr, 0)
        yield
    
    @pytest.mark.asyncio
    async def test_full_error_handling_workflow(self):
        """Test complete error handling workflow from WebSocket to Dispatcher"""
        router = Router()
        dispatcher = MessageDispatcher(router)
        
        class MultiErrorMiddleware(BaseMiddleware):
            def __init__(self):
                self.call_count = 0
            
            async def on_message(self, call_next, websocket, message_data):
                self.call_count += 1
                message_type = message_data.get('error_type')
                
                if message_type == 'client':
                    raise MessageValidationError("Client sent invalid data")
                elif message_type == 'server':
                    raise MiddlewareError("Server middleware error")
                elif message_type == 'recoverable':
                    if self.call_count == 1:
                        raise asyncio.TimeoutError("Temporary timeout")
                elif message_type == 'fatal':
                    raise MemoryError("System out of memory")
                
                await call_next(websocket, message_data)
        
        middleware = MultiErrorMiddleware()
        dispatcher.add_middleware(middleware)
        
        handler_processed = False
        
        @router.message()
        async def message_handler(websocket, message):
            nonlocal handler_processed
            handler_processed = True
        
        mock_websocket = Mock()
        mock_websocket.context = {}
        mock_websocket.remote_address = ('127.0.0.1', 8080)
        mock_websocket.closed = False
        mock_websocket.close = AsyncMock()
        
        message_data = {"type": "chat", "text": "test", "user_id": 1, "error_type": "client"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.client_errors == 1
        assert not handler_processed
        
        handler_processed = False
        
        message_data = {"type": "chat", "text": "test", "user_id": 1, "error_type": "server"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.server_errors == 1
        assert handler_processed
        
        handler_processed = False
        
        middleware.call_count = 0
        
        message_data = {"type": "chat", "text": "test", "user_id": 1, "error_type": "recoverable"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.recoverable_errors == 1
        assert not handler_processed
        
        handler_processed = False
        message_data = {"type": "chat", "text": "test", "user_id": 1, "error_type": "recoverable"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert handler_processed
        
        message_data = {"type": "chat", "text": "test", "user_id": 1, "error_type": "fatal"}
        await dispatcher.dispatch_message(mock_websocket, message_data)
        
        assert dispatcher_error_metrics.fatal_errors == 1
    
    @pytest.mark.asyncio
    async def test_metrics_consistency_across_components(self):
        """Test that metrics are consistent across WebSocket and Dispatcher components"""
        validation_error = MessageValidationError("Test validation error")
        connection_error = ConnectionError("Test connection error")
        memory_error = MemoryError("Test memory error")
        timeout_error = asyncio.TimeoutError("Test timeout error")
        
        assert ErrorCategorizer.categorize_exception(validation_error) == ErrorCategory.CLIENT_ERROR
        assert ErrorCategorizer.categorize_exception(connection_error) == ErrorCategory.SERVER_ERROR
        assert ErrorCategorizer.categorize_exception(memory_error) == ErrorCategory.FATAL
        assert ErrorCategorizer.categorize_exception(timeout_error) == ErrorCategory.RECOVERABLE
        
        assert ErrorCategorizer.get_log_level(validation_error) == 'warning'
        assert ErrorCategorizer.get_log_level(connection_error) == 'error'
        assert ErrorCategorizer.get_log_level(memory_error) == 'critical'
        assert ErrorCategorizer.get_log_level(timeout_error) == 'info'
        
        assert ErrorCategorizer.should_stop_middleware_chain(validation_error) == True
        assert ErrorCategorizer.should_stop_middleware_chain(connection_error) == True
        assert ErrorCategorizer.should_stop_middleware_chain(memory_error) == True
        assert ErrorCategorizer.should_stop_middleware_chain(timeout_error) == True
        
        regular_error = MiddlewareError("Regular error")
        assert ErrorCategorizer.should_stop_middleware_chain(regular_error, "LoggingMiddleware") == False 