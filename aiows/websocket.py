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
from .exceptions import ConnectionError, MessageSizeError

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
    
    def increment(self, error_type: str):
        if hasattr(self, f"{error_type}_errors"):
            setattr(self, f"{error_type}_errors", getattr(self, f"{error_type}_errors") + 1)

error_metrics = ErrorMetrics()


class WebSocket:
    """WebSocket connection wrapper for aiows framework"""
    
    def __init__(self, websocket, operation_timeout: float = DEFAULT_OPERATION_TIMEOUT, 
                 max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE):
        self._websocket = websocket
        self.context: Dict[str, Any] = {}
        
        # Optimized connection state management with asyncio.Event
        self._is_closed_event = asyncio.Event()
        self._is_closed_event.clear()  # Start as not closed
        
        # Separate locks for send and receive operations for better concurrency
        self._send_lock = asyncio.Lock()
        self._receive_lock = asyncio.Lock()
        
        # Close operation still needs protection with dedicated lock
        self._close_lock = asyncio.Lock()
        
        self._operation_timeout = operation_timeout
        self._max_message_size = max_message_size
        self._error_count = 0
        
        if max_message_size <= 0:
            raise ValueError("max_message_size must be positive")
    
    # Lock-free connection state checks for better performance
    @property
    def _is_closed(self) -> bool:
        """Lock-free connection state check"""
        return self._is_closed_event.is_set()
    
    def _mark_as_closed(self):
        """Mark connection as closed (thread-safe)"""
        self._is_closed_event.set()
    
    def _reset_connection_state_for_testing(self):
        """Reset connection state for testing purposes ONLY"""
        self._is_closed_event.clear()
        self._error_count = 0
    
    def _log_error_with_context(self, error: Exception, operation: str, additional_context: Dict[str, Any] = None):
        context = {
            'operation': operation,
            'remote_address': self.remote_address,
            'is_closed': self._is_closed,
            'error_count': self._error_count,
            'error_type': type(error).__name__,
            'operation_timeout': self._operation_timeout,
        }
        if additional_context:
            context.update(additional_context)
        
        logger.error(f"WebSocket {operation} error: {error}", extra={'context': context})
    
    def _handle_critical_error(self, error: Exception, operation: str):
        self._error_count += 1
        self._mark_as_closed()
        self._log_error_with_context(error, operation, {'critical': True})
    
    async def send_json(self, data: dict) -> None:
        # Lock-free connection state check for performance
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        # Separate send lock allows concurrent receive operations
        async with self._send_lock:
            # Double-check pattern for connection state
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                def json_serializer(obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
                
                json_data = json.dumps(data, default=json_serializer)
                
                # Remove asyncio.wait_for() for better performance in send operations
                await self._websocket.send(json_data)
                
                self._error_count = 0
                
            except asyncio.TimeoutError as e:
                # Handle TimeoutError specifically for backwards compatibility
                error_metrics.increment('timeout')
                self._handle_critical_error(e, 'send_json')
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except (TypeError, ValueError) as e:
                error_metrics.increment('json')
                self._log_error_with_context(e, 'send_json', {'json_serialization': True})
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
                logger.critical(f"Unexpected error in send_json: {type(e).__name__}: {e}")
                raise ConnectionError(f"Unexpected error during send: {str(e)}")
    
    async def send_message(self, message: BaseMessage) -> None:
        await self.send_json(message.dict())
    
    async def receive_json(self) -> dict:
        # Lock-free connection state check for performance
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        # Separate receive lock allows concurrent send operations
        async with self._receive_lock:
            # Double-check pattern for connection state
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Remove asyncio.wait_for() for better performance in receive operations
                raw_data = await self._websocket.recv()
                
                # Handle potential None return from mock objects or protocol errors
                if raw_data is None:
                    error_metrics.increment('connection')
                    self._handle_critical_error(Exception("Received None data"), 'receive_json')
                    raise ConnectionError("WebSocket protocol error: received None data")
                
                message_size = len(raw_data)
                if message_size > self._max_message_size:
                    error_metrics.increment('size')
                    logger.warning(f"Oversized JSON message blocked: {message_size} bytes (limit: {self._max_message_size})")
                    raise MessageSizeError(f"Message size {message_size} exceeds limit {self._max_message_size}")
                
                try:
                    result = json.loads(raw_data)
                    self._error_count = 0
                    return result
                except json.JSONDecodeError as e:
                    error_metrics.increment('json')
                    self._log_error_with_context(e, 'receive_json', {
                        'message_size': message_size,
                        'raw_data_preview': raw_data[:100] if len(raw_data) > 100 else raw_data
                    })
                    raise ConnectionError(f"Invalid JSON received: {str(e)}")
                
            except asyncio.TimeoutError as e:
                # Handle TimeoutError specifically for backwards compatibility
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
                logger.critical(f"Unexpected error in receive_json: {type(e).__name__}: {e}")
                raise ConnectionError(f"Unexpected error during receive: {str(e)}")
    
    async def recv(self) -> str:
        # Lock-free connection state check for performance
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        # Separate receive lock allows concurrent send operations
        async with self._receive_lock:
            # Double-check pattern for connection state
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Remove asyncio.wait_for() for better performance in receive operations
                raw_data = await self._websocket.recv()
                
                # Handle potential None return from mock objects or protocol errors
                if raw_data is None:
                    error_metrics.increment('connection')
                    self._handle_critical_error(Exception("Received None data"), 'recv')
                    raise ConnectionError("WebSocket protocol error: received None data")
                
                message_size = len(raw_data)
                if message_size > self._max_message_size:
                    error_metrics.increment('size')
                    logger.warning(f"Oversized message blocked: {message_size} bytes (limit: {self._max_message_size})")
                    raise MessageSizeError(f"Message size {message_size} exceeds limit {self._max_message_size}")
                
                self._error_count = 0
                return raw_data
                
            except asyncio.TimeoutError as e:
                # Handle TimeoutError specifically for backwards compatibility
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
                logger.critical(f"Unexpected error in recv: {type(e).__name__}: {e}")
                raise ConnectionError(f"Unexpected error during receive: {str(e)}")
    
    async def send(self, data: str) -> None:
        # Lock-free connection state check for performance
        if self._is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        # Separate send lock allows concurrent receive operations
        async with self._send_lock:
            # Double-check pattern for connection state
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Remove asyncio.wait_for() for better performance in send operations
                await self._websocket.send(data)
                
                self._error_count = 0
                
            except asyncio.TimeoutError as e:
                # Handle TimeoutError specifically for backwards compatibility
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
                logger.critical(f"Unexpected error in send: {type(e).__name__}: {e}")
                raise ConnectionError(f"Unexpected error during send: {str(e)}")
    
    async def close(self, code: int = 1000, reason: str = "") -> None:
        # Use dedicated close lock to prevent concurrent close operations
        async with self._close_lock:
            if self._is_closed:
                logger.debug("WebSocket connection already closed, ignoring close() call")
                return
            
            self._mark_as_closed()
            
            try:
                # Keep asyncio.wait_for() only for close operation as required
                await asyncio.wait_for(
                    self._websocket.close(code=code, reason=reason),
                    timeout=self._operation_timeout
                )
                logger.debug(f"WebSocket connection closed gracefully with code {code}")
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                logger.warning(f"WebSocket close operation timed out after {self._operation_timeout} seconds")
            
            except asyncio.CancelledError:
                logger.debug("WebSocket close operation was cancelled")
                raise
            
            except (socket.error, OSError) as e:
                logger.debug(f"Network error during WebSocket close: {str(e)}")
            
            except ssl.SSLError as e:
                logger.debug(f"SSL error during WebSocket close: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                logger.debug(f"Protocol error during WebSocket close: {str(e)}")
            
            except Exception as e:
                logger.warning(f"Unexpected error during WebSocket close: {type(e).__name__}: {e}")
    
    @property
    def closed(self) -> bool:
        """Lock-free connection state check"""
        return self._is_closed
    
    @property  
    def is_closed(self) -> bool:
        """Lock-free connection state check"""
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