"""
WebSocket connection wrapper
"""

import asyncio
import logging
from typing import Dict, Any
import json
from datetime import datetime
import socket
import ssl
from .types import BaseMessage
from .exceptions import ConnectionError, MessageSizeError, ErrorCategory, ErrorContext, ErrorCategorizer

logger = logging.getLogger(__name__)

DEFAULT_OPERATION_TIMEOUT = 30.0
DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024

class ErrorMetrics:
    """Simple error metrics collector"""
    def __init__(self):
        self.connection_errors = 0
        self.timeout_errors = 0
        self.json_errors = 0
        self.size_errors = 0
        self.network_errors = 0
        self.ssl_errors = 0
        self.unexpected_errors = 0
        
        self.fatal_errors = 0
        self.recoverable_errors = 0
        self.client_errors = 0
        self.server_errors = 0
    
    def increment(self, error_type: str):
        if hasattr(self, f"{error_type}_errors"):
            setattr(self, f"{error_type}_errors", getattr(self, f"{error_type}_errors") + 1)
    
    def increment_category(self, category: ErrorCategory):
        category_map = {
            ErrorCategory.FATAL: 'fatal',
            ErrorCategory.RECOVERABLE: 'recoverable', 
            ErrorCategory.CLIENT_ERROR: 'client',
            ErrorCategory.SERVER_ERROR: 'server'
        }
        
        category_name = category_map.get(category, 'server')
        self.increment(category_name)


error_metrics = ErrorMetrics()


class WebSocket:
    """WebSocket connection wrapper for aiows framework"""
    
    def __init__(self, websocket, operation_timeout: float = DEFAULT_OPERATION_TIMEOUT, 
                 max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE):
        self._websocket = websocket
        self.context: Dict[str, Any] = {}
        
        self._is_closed_event = asyncio.Event()
        self._is_closed_event.clear()
        
        self._send_lock = asyncio.Lock()
        self._receive_lock = asyncio.Lock()
        
        self._close_lock = asyncio.Lock()
        
        self._operation_timeout = operation_timeout
        self._max_message_size = max_message_size
        self._error_count = 0
        
        if max_message_size <= 0:
            raise ValueError("max_message_size must be positive")
    
    @property
    def _is_closed(self) -> bool:
        return self._is_closed_event.is_set()
    
    def _mark_as_closed(self):
        self._is_closed_event.set()
    
    def _reset_connection_state_for_testing(self):
        self._is_closed_event.clear()
        self._error_count = 0
    
    def _create_error_context(self, operation: str, additional_context: Dict[str, Any] = None) -> ErrorContext:
        context_data = {
            'remote_address': self.remote_address,
            'is_closed': self._is_closed,
            'error_count': self._error_count,
            'operation_timeout': self._operation_timeout,
        }
        
        if additional_context:
            context_data.update(additional_context)
        
        return ErrorContext(
            operation=operation,
            component='websocket',
            additional_context=context_data
        )
    
    def _log_error_with_context(self, error: Exception, context: ErrorContext):
        category = ErrorCategorizer.categorize_exception(error)
        log_level = ErrorCategorizer.get_log_level(error)
        
        log_method = getattr(logger, log_level, logger.error)
        
        message = f"WebSocket {context.operation} error: {error}"
        
        extra_data = {
            'error_category': category.value,
            'error_type': type(error).__name__,
            'error_id': context.error_id,
            'context': context.to_dict()
        }
        
        log_method(message, extra=extra_data)
        
        error_metrics.increment_category(category)
    
    def _handle_critical_error(self, error: Exception, operation: str):
        self._error_count += 1
        self._mark_as_closed()
        
        context = self._create_error_context(operation, {'critical': True})
        self._log_error_with_context(error, context)
    
    async def send_json(self, data: dict) -> None:
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        async with self._send_lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                def json_serializer(obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
                
                json_data = json.dumps(data, default=json_serializer)
                
                await self._websocket.send(json_data)
                
                self._error_count = 0
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except (TypeError, ValueError) as e:
                error_metrics.increment('json')
                context = self._create_error_context('send_json', {'json_serialization': True})
                self._log_error_with_context(e, context)
                raise ConnectionError(f"JSON serialization failed: {str(e)}")
            
            except (socket.error, OSError) as e:
                error_metrics.increment('network')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"Network error during send: {str(e)}")
            
            except ssl.SSLError as e:
                error_metrics.increment('ssl')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"SSL error during send: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                error_metrics.increment('connection')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"WebSocket protocol error: {str(e)}")
            
            except Exception as e:
                error_metrics.increment('unexpected')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"Unexpected error during send: {str(e)}")
    
    async def send_message(self, message: BaseMessage) -> None:
        await self.send_json(message.dict())
    
    async def receive_json(self) -> dict:
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        async with self._receive_lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                raw_data = await self._websocket.recv()
                
                if raw_data is None:
                    error_metrics.increment('connection')
                    self._handle_critical_error(Exception("Received None data"), 'receive_json')
                    raise ConnectionError("WebSocket protocol error: received None data")
                
                message_size = len(raw_data)
                if message_size > self._max_message_size:
                    error_metrics.increment('size')
                    context = self._create_error_context('receive_json', {'message_size': message_size})
                    oversized_error = MessageSizeError(f"Message size {message_size} exceeds limit {self._max_message_size}")
                    self._log_error_with_context(oversized_error, context)
                    logger.warning(f"Oversized JSON message blocked: {message_size} bytes (limit: {self._max_message_size})")
                    raise oversized_error
                
                try:
                    result = json.loads(raw_data)
                    self._error_count = 0
                    return result
                except json.JSONDecodeError as e:
                    error_metrics.increment('json')
                    context = self._create_error_context('receive_json', {
                        'message_size': message_size,
                        'raw_data_preview': raw_data[:100] if len(raw_data) > 100 else raw_data
                    })
                    self._log_error_with_context(e, context)
                    raise ConnectionError(f"Invalid JSON received: {str(e)}")
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                self._handle_critical_error(e, 'receive_json')
                raise ConnectionError(f"Receive operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except MessageSizeError:
                raise
            
            except (socket.error, OSError) as e:
                error_metrics.increment('network')
                self._handle_critical_error(e, 'receive_json')
                raise ConnectionError(f"Network error during receive: {str(e)}")
            
            except ssl.SSLError as e:
                error_metrics.increment('ssl')
                self._handle_critical_error(e, 'receive_json')
                raise ConnectionError(f"SSL error during receive: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                error_metrics.increment('connection')
                self._handle_critical_error(e, 'receive_json')
                raise ConnectionError(f"WebSocket protocol error: {str(e)}")
            
            except Exception as e:
                error_metrics.increment('unexpected')
                self._handle_critical_error(e, 'receive_json')
                raise ConnectionError(f"Unexpected error during receive: {str(e)}")
    
    async def recv(self) -> str:
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        async with self._receive_lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                raw_data = await self._websocket.recv()
                
                if raw_data is None:
                    error_metrics.increment('connection')
                    self._handle_critical_error(Exception("Received None data"), 'recv')
                    raise ConnectionError("WebSocket protocol error: received None data")
                
                message_size = len(raw_data)
                if message_size > self._max_message_size:
                    error_metrics.increment('size')
                    context = self._create_error_context('recv', {'message_size': message_size})
                    oversized_error = MessageSizeError(f"Message size {message_size} exceeds limit {self._max_message_size}")
                    self._log_error_with_context(oversized_error, context)
                    logger.warning(f"Oversized message blocked: {message_size} bytes (limit: {self._max_message_size})")
                    raise oversized_error
                
                self._error_count = 0
                return raw_data
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                self._handle_critical_error(e, 'recv')
                raise ConnectionError(f"Receive operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except MessageSizeError:
                raise
            
            except ssl.SSLError as e:
                error_metrics.increment('ssl')
                self._handle_critical_error(e, 'recv')
                raise ConnectionError(f"SSL error during receive: {str(e)}")
            
            except (socket.error, OSError) as e:
                error_metrics.increment('network')
                self._handle_critical_error(e, 'recv')
                raise ConnectionError(f"Network error during receive: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                error_metrics.increment('connection')
                self._handle_critical_error(e, 'recv')
                raise ConnectionError(f"WebSocket protocol error: {str(e)}")
            
            except Exception as e:
                error_metrics.increment('unexpected')
                self._handle_critical_error(e, 'recv')
                raise ConnectionError(f"Unexpected error during receive: {str(e)}")
    
    async def send(self, data: str) -> None:
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        async with self._send_lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                await self._websocket.send(data)
                
                self._error_count = 0
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                self._handle_critical_error(e, 'send')
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except (socket.error, OSError) as e:
                error_metrics.increment('network')
                self._handle_critical_error(e, 'send')
                raise ConnectionError(f"Network error during send: {str(e)}")
            
            except ssl.SSLError as e:
                error_metrics.increment('ssl')
                self._handle_critical_error(e, 'send')
                raise ConnectionError(f"SSL error during send: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                error_metrics.increment('connection')
                self._handle_critical_error(e, 'send')
                raise ConnectionError(f"WebSocket protocol error: {str(e)}")
            
            except Exception as e:
                error_metrics.increment('unexpected')
                self._handle_critical_error(e, 'send')
                raise ConnectionError(f"Unexpected error during send: {str(e)}")
    
    async def close(self, code: int = 1000, reason: str = "") -> None:
        async with self._close_lock:
            if self._is_closed:
                logger.debug("WebSocket connection already closed, ignoring close() call")
                return
            
            self._mark_as_closed()
            
            try:
                await asyncio.wait_for(
                    self._websocket.close(code=code, reason=reason),
                    timeout=self._operation_timeout
                )
                logger.debug(f"WebSocket connection closed gracefully with code {code}")
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                context = self._create_error_context('close', {'timeout': True, 'code': code})
                self._log_error_with_context(e, context)
                logger.warning(f"WebSocket close operation timed out after {self._operation_timeout} seconds")
            
            except asyncio.CancelledError:
                logger.debug("WebSocket close operation was cancelled")
                raise
            
            except (socket.error, OSError) as e:
                context = self._create_error_context('close', {'network_error': True, 'code': code})
                self._log_error_with_context(e, context)
                logger.debug(f"Network error during WebSocket close: {str(e)}")
            
            except ssl.SSLError as e:
                context = self._create_error_context('close', {'ssl_error': True, 'code': code})
                self._log_error_with_context(e, context)
                logger.debug(f"SSL error during WebSocket close: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                context = self._create_error_context('close', {'protocol_error': True, 'code': code})
                self._log_error_with_context(e, context)
                logger.debug(f"Protocol error during WebSocket close: {str(e)}")
            
            except Exception as e:
                context = self._create_error_context('close', {'unexpected': True, 'code': code})
                self._log_error_with_context(e, context)
                logger.warning(f"Unexpected error during WebSocket close: {type(e).__name__}: {e}")
    
    @property
    def closed(self) -> bool:
        return self._is_closed
    
    @property  
    def is_closed(self) -> bool:
        return self._is_closed
    
    @property
    def remote_address(self) -> tuple:
        try:
            return getattr(self._websocket, 'remote_address', ('unknown', 0))
        except (AttributeError, OSError, RuntimeError) as e:
            logger.debug(f"Could not get remote address: {type(e).__name__}: {e}")
            return ('unknown', 0)
        except Exception as e:
            logger.warning(f"Unexpected error getting remote address: {type(e).__name__}: {e}")
            return ('unknown', 0)
    
    def set_operation_timeout(self, timeout: float) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self._operation_timeout = timeout 
        
    @property
    def error_metrics(self) -> ErrorMetrics:
        return error_metrics 