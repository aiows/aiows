import asyncio
import logging
from typing import Dict, Any, Optional, Deque, Union
import json
from datetime import datetime
import socket
import ssl
import time
from collections import deque
from .types import BaseMessage
from .exceptions import ConnectionError, MessageSizeError, ErrorCategory, ErrorContext, ErrorCategorizer

logger = logging.getLogger(__name__)

DEFAULT_OPERATION_TIMEOUT = 30.0
DEFAULT_MAX_MESSAGE_SIZE = 1024 * 1024

class ErrorMetrics:
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


class BackpressureMetrics:
    def __init__(self):
        self.messages_queued = 0
        self.messages_sent = 0
        self.messages_dropped = 0
        self.queue_overflow_events = 0
        self.slow_client_disconnections = 0
        self.avg_queue_size = 0.0
        self.max_queue_size_reached = 0
        self.total_send_time_ms = 0.0
        self.send_timeouts = 0
        
        self.connection_metrics: Dict[str, Dict[str, Any]] = {}
        self._start_time = time.time()
    
    def record_message_queued(self, connection_id: str, queue_size: int):
        self.messages_queued += 1
        self._update_connection_metric(connection_id, 'messages_queued', 1)
        self._update_connection_metric(connection_id, 'current_queue_size', queue_size)
        
        if queue_size > self.max_queue_size_reached:
            self.max_queue_size_reached = queue_size
    
    def record_message_sent(self, connection_id: str, send_time_ms: float, queue_size: int):
        self.messages_sent += 1
        self.total_send_time_ms += send_time_ms
        self._update_connection_metric(connection_id, 'messages_sent', 1)
        self._update_connection_metric(connection_id, 'total_send_time_ms', send_time_ms)
        self._update_connection_metric(connection_id, 'current_queue_size', queue_size)
    
    def record_message_dropped(self, connection_id: str, reason: str):
        self.messages_dropped += 1
        self._update_connection_metric(connection_id, 'messages_dropped', 1)
        self._update_connection_metric(connection_id, 'last_drop_reason', reason)
    
    def record_queue_overflow(self, connection_id: str):
        self.queue_overflow_events += 1
        self._update_connection_metric(connection_id, 'queue_overflows', 1)
    
    def record_slow_client_disconnect(self, connection_id: str):
        self.slow_client_disconnections += 1
        self._update_connection_metric(connection_id, 'disconnected_for_slowness', True)
    
    def record_send_timeout(self, connection_id: str):
        self.send_timeouts += 1
        self._update_connection_metric(connection_id, 'send_timeouts', 1)
    
    def _update_connection_metric(self, connection_id: str, metric: str, value: Union[int, float, str, bool]):
        if connection_id not in self.connection_metrics:
            self.connection_metrics[connection_id] = {
                'created_at': time.time(),
                'messages_queued': 0,
                'messages_sent': 0,
                'messages_dropped': 0,
                'queue_overflows': 0,
                'send_timeouts': 0,
                'total_send_time_ms': 0.0,
                'current_queue_size': 0,
                'disconnected_for_slowness': False,
                'last_drop_reason': None
            }
        
        if metric in ['messages_queued', 'messages_sent', 'messages_dropped', 'queue_overflows', 'send_timeouts']:
            self.connection_metrics[connection_id][metric] += value
        elif metric == 'total_send_time_ms':
            self.connection_metrics[connection_id][metric] += value
        else:
            self.connection_metrics[connection_id][metric] = value
    
    def get_connection_stats(self, connection_id: str) -> Dict[str, Any]:
        return self.connection_metrics.get(connection_id, {})
    
    def get_global_stats(self) -> Dict[str, Any]:
        uptime_seconds = time.time() - self._start_time
        avg_send_time = self.total_send_time_ms / max(1, self.messages_sent)
        
        return {
            'uptime_seconds': uptime_seconds,
            'messages_queued': self.messages_queued,
            'messages_sent': self.messages_sent,
            'messages_dropped': self.messages_dropped,
            'queue_overflow_events': self.queue_overflow_events,
            'slow_client_disconnections': self.slow_client_disconnections,
            'max_queue_size_reached': self.max_queue_size_reached,
            'average_send_time_ms': avg_send_time,
            'send_timeouts': self.send_timeouts,
            'active_connections': len(self.connection_metrics),
            'throughput_messages_per_second': self.messages_sent / max(1, uptime_seconds)
        }
    
    def cleanup_connection(self, connection_id: str):
        self.connection_metrics.pop(connection_id, None)


class SendQueueItem:
    def __init__(self, data: str, created_at: float, item_type: str = "data"):
        self.data = data
        self.created_at = created_at
        self.item_type = item_type


class BackpressureManager:
    def __init__(self, connection_id: str, max_queue_size: int = 100, 
                 overflow_strategy: str = "drop_oldest",
                 slow_client_threshold: int = 80,
                 slow_client_timeout: float = 60.0,
                 max_response_time_ms: int = 5000,
                 enable_metrics: bool = True):
        self.connection_id = connection_id
        self.max_queue_size = max_queue_size
        self.overflow_strategy = overflow_strategy
        self.slow_client_threshold = slow_client_threshold
        self.slow_client_timeout = slow_client_timeout
        self.max_response_time_ms = max_response_time_ms
        self.enable_metrics = enable_metrics
        
        self.send_queue: Deque[SendQueueItem] = deque()
        self.is_processing = False
        self.last_successful_send = time.time()
        self.slow_client_detected_at: Optional[float] = None
        
        self._queue_lock = asyncio.Lock()
        self._metrics = BackpressureMetrics() if enable_metrics else None
    
    @property
    def queue_size(self) -> int:
        return len(self.send_queue)
    
    @property
    def queue_utilization_percent(self) -> float:
        return (self.queue_size / max(1, self.max_queue_size)) * 100
    
    @property
    def is_queue_full(self) -> bool:
        return self.queue_size >= self.max_queue_size
    
    @property
    def is_slow_client(self) -> bool:
        threshold_size = int(self.max_queue_size * (self.slow_client_threshold / 100))
        return self.queue_size >= threshold_size
    
    @property
    def should_disconnect_slow_client(self) -> bool:
        if not self.slow_client_detected_at:
            return False
        
        elapsed = time.time() - self.slow_client_detected_at
        return elapsed >= self.slow_client_timeout
    
    async def enqueue_message(self, data: str, item_type: str = "data") -> bool:
        async with self._queue_lock:
            current_time = time.time()
            was_slow_before = self.slow_client_detected_at is not None
            
            if self.is_queue_full:
                if self._metrics:
                    self._metrics.record_queue_overflow(self.connection_id)
                
                if self.overflow_strategy == "drop_oldest":
                    if self.send_queue:
                        dropped_item = self.send_queue.popleft()
                        if self._metrics:
                            self._metrics.record_message_dropped(self.connection_id, "queue_overflow_drop_oldest")
                        logger.debug(f"Dropped oldest message from queue for connection {self.connection_id}")
                elif self.overflow_strategy == "drop_newest":
                    if self._metrics:
                        self._metrics.record_message_dropped(self.connection_id, "queue_overflow_drop_newest")
                    logger.debug(f"Dropped newest message from queue for connection {self.connection_id}")
                    return False
                elif self.overflow_strategy == "reject":
                    if self._metrics:
                        self._metrics.record_message_dropped(self.connection_id, "queue_overflow_reject")
                    logger.warning(f"Message rejected due to full queue for connection {self.connection_id}")
                    return False
            
            queue_item = SendQueueItem(data, current_time, item_type)
            self.send_queue.append(queue_item)
            
            if self.is_slow_client and not was_slow_before:
                self.slow_client_detected_at = current_time
                logger.warning(f"Slow client detected for connection {self.connection_id}, queue size: {self.queue_size}")
            elif not self.is_slow_client and was_slow_before:
                self.slow_client_detected_at = None
            
            if self._metrics:
                self._metrics.record_message_queued(self.connection_id, self.queue_size)
            
            return True
    
    async def dequeue_message(self) -> Optional[SendQueueItem]:
        async with self._queue_lock:
            if self.send_queue:
                return self.send_queue.popleft()
            return None
    
    def record_successful_send(self, send_time_ms: float):
        self.last_successful_send = time.time()
        if self._metrics:
            self._metrics.record_message_sent(self.connection_id, send_time_ms, self.queue_size)
        
        if not self.is_slow_client:
            self.slow_client_detected_at = None
    
    def record_send_timeout(self):
        if self._metrics:
            self._metrics.record_send_timeout(self.connection_id)
    
    def get_health_stats(self) -> Dict[str, Any]:
        current_time = time.time()
        time_since_last_send = current_time - self.last_successful_send
        
        stats = {
            'connection_id': self.connection_id,
            'queue_size': self.queue_size,
            'queue_utilization_percent': self.queue_utilization_percent,
            'is_slow_client': self.is_slow_client,
            'time_since_last_send_seconds': time_since_last_send,
            'slow_client_detected_at': self.slow_client_detected_at,
            'should_disconnect': self.should_disconnect_slow_client,
            'is_processing': self.is_processing
        }
        
        if self._metrics:
            stats.update(self._metrics.get_connection_stats(self.connection_id))
        
        return stats
    
    def cleanup(self):
        if self._metrics:
            self._metrics.cleanup_connection(self.connection_id)


backpressure_metrics = BackpressureMetrics()


class WebSocket:
    def __init__(self, websocket, operation_timeout: float = DEFAULT_OPERATION_TIMEOUT, 
                 max_message_size: int = DEFAULT_MAX_MESSAGE_SIZE,
                 backpressure_settings: Optional[Dict[str, Any]] = None):
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
        
        self._connection_id = f"ws_{id(self)}_{time.time()}"
        self._backpressure_enabled = False
        self._backpressure_manager: Optional[BackpressureManager] = None
        self._send_task: Optional[asyncio.Task] = None
        
        if backpressure_settings:
            self._init_backpressure(backpressure_settings)
    
    def _init_backpressure(self, settings: Dict[str, Any]):
        self._backpressure_enabled = settings.get('enabled', True)
        
        if self._backpressure_enabled:
            self._backpressure_manager = BackpressureManager(
                connection_id=self._connection_id,
                max_queue_size=settings.get('send_queue_max_size', 100),
                overflow_strategy=settings.get('send_queue_overflow_strategy', 'drop_oldest'),
                slow_client_threshold=settings.get('slow_client_threshold', 80),
                slow_client_timeout=settings.get('slow_client_timeout', 60.0),
                max_response_time_ms=settings.get('max_response_time_ms', 5000),
                enable_metrics=settings.get('enable_send_metrics', True)
            )
            
            self._send_task = None
            self._start_background_worker()
    
    def _start_background_worker(self):
        try:
            if self._send_task is None or self._send_task.done():
                self._send_task = asyncio.create_task(self._background_send_worker())
        except RuntimeError:
            pass
    
    def _ensure_background_worker(self):
        if self._backpressure_enabled and self._backpressure_manager:
            if self._send_task is None or self._send_task.done():
                try:
                    self._send_task = asyncio.create_task(self._background_send_worker())
                except RuntimeError:
                    logger.warning(f"Cannot start background worker for {self._connection_id}: no event loop")
    
    async def _background_send_worker(self):
        if not self._backpressure_manager:
            return
        
        logger.debug(f"Started background send worker for connection {self._connection_id}")
        
        try:
            while not self._is_closed and self._backpressure_enabled:
                try:
                    if self._backpressure_manager.should_disconnect_slow_client:
                        logger.warning(f"Disconnecting slow client {self._connection_id}")
                        backpressure_metrics.record_slow_client_disconnect(self._connection_id)
                        await self.close(code=1008, reason="Slow client detected")
                        break
                    
                    queue_item = await self._backpressure_manager.dequeue_message()
                    if queue_item is None:
                        await asyncio.sleep(0.01)
                        continue
                    
                    start_time = time.time()
                    self._backpressure_manager.is_processing = True
                    
                    try:
                        await asyncio.wait_for(
                            self._websocket.send(queue_item.data),
                            timeout=self._operation_timeout
                        )
                        
                        send_time_ms = (time.time() - start_time) * 1000
                        self._backpressure_manager.record_successful_send(send_time_ms)
                        
                        if send_time_ms > self._backpressure_manager.max_response_time_ms:
                            logger.warning(f"Slow send detected for connection {self._connection_id}: {send_time_ms:.1f}ms")
                        
                    except asyncio.TimeoutError:
                        self._backpressure_manager.record_send_timeout()
                        logger.warning(f"Send timeout for connection {self._connection_id}")
                    
                    except Exception as e:
                        logger.error(f"Send error in background worker for {self._connection_id}: {e}")
                        if "closed" in str(e).lower() or "broken" in str(e).lower():
                            break
                    
                    finally:
                        self._backpressure_manager.is_processing = False
                
                except asyncio.CancelledError:
                    logger.debug(f"Background send worker cancelled for {self._connection_id}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in background send worker for {self._connection_id}: {e}")
                    await asyncio.sleep(0.1)
        
        finally:
            logger.debug(f"Background send worker finished for connection {self._connection_id}")
            if self._backpressure_manager:
                self._backpressure_manager.is_processing = False

    @property
    def _is_closed(self) -> bool:
        return self._is_closed_event.is_set()
    
    def _mark_as_closed(self):
        self._is_closed_event.set()
        
        if self._send_task and not self._send_task.done():
            self._send_task.cancel()
        
        if self._backpressure_manager:
            self._backpressure_manager.cleanup()
    
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
        
        try:
            def json_serializer(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
            
            json_data = json.dumps(data, default=json_serializer)
            
            if self._backpressure_enabled and self._backpressure_manager:
                self._ensure_background_worker()
                success = await self._backpressure_manager.enqueue_message(json_data, "json")
                if not success:
                    raise ConnectionError("Failed to queue message: queue overflow")
                return
            
            await self._direct_send(json_data, 'send_json')
            
        except (TypeError, ValueError) as e:
            error_metrics.increment('json')
            context = self._create_error_context('send_json', {'json_serialization': True})
            self._log_error_with_context(e, context)
            raise ConnectionError(f"JSON serialization failed: {str(e)}")
        
        except ConnectionError:
            raise
        
        except Exception as e:
            error_metrics.increment('unexpected')
            self._handle_critical_error(e, 'send_json')
            raise ConnectionError(f"Unexpected error during send: {str(e)}")
    
    async def _direct_send(self, data: str, operation: str) -> None:
        async with self._send_lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                await self._websocket.send(data)
                self._error_count = 0
                
            except asyncio.TimeoutError as e:
                error_metrics.increment('timeout')
                self._handle_critical_error(e, operation)
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
                
            except asyncio.CancelledError:
                self._mark_as_closed()
                raise
            
            except (socket.error, OSError) as e:
                error_metrics.increment('network')
                self._handle_critical_error(e, operation)
                raise ConnectionError(f"Network error during send: {str(e)}")
            
            except ssl.SSLError as e:
                error_metrics.increment('ssl')
                self._handle_critical_error(e, operation)
                raise ConnectionError(f"SSL error during send: {str(e)}")
            
            except (AttributeError, RuntimeError) as e:
                error_metrics.increment('connection')
                self._handle_critical_error(e, operation)
                raise ConnectionError(f"WebSocket protocol error: {str(e)}")
            
            except Exception as e:
                error_metrics.increment('unexpected')
                self._handle_critical_error(e, operation)
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
        
        if self._backpressure_enabled and self._backpressure_manager:
            self._ensure_background_worker()
            success = await self._backpressure_manager.enqueue_message(data, "data")
            if not success:
                raise ConnectionError("Failed to queue message: queue overflow")
            return
        
        await self._direct_send(data, 'send')
    
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
    
    def enable_backpressure(self, settings: Dict[str, Any]) -> None:
        if not self._backpressure_enabled:
            self._init_backpressure(settings)
    
    def disable_backpressure(self) -> None:
        self._backpressure_enabled = False
        
        if self._send_task and not self._send_task.done():
            self._send_task.cancel()
        
        if self._backpressure_manager:
            self._backpressure_manager.cleanup()
            self._backpressure_manager = None
    
    def get_backpressure_stats(self) -> Dict[str, Any]:
        if not self._backpressure_manager:
            return {
                'backpressure_enabled': False,
                'connection_id': self._connection_id
            }
        
        stats = self._backpressure_manager.get_health_stats()
        stats['backpressure_enabled'] = self._backpressure_enabled
        return stats
    
    @property
    def connection_id(self) -> str:
        return self._connection_id
    
    @property
    def backpressure_enabled(self) -> bool:
        return self._backpressure_enabled
    
    @property
    def send_queue_size(self) -> int:
        if self._backpressure_manager:
            return self._backpressure_manager.queue_size
        return 0
    
    @property
    def send_queue_utilization_percent(self) -> float:
        if self._backpressure_manager:
            return self._backpressure_manager.queue_utilization_percent
        return 0.0
        
    @property
    def error_metrics(self) -> ErrorMetrics:
        return error_metrics
    
    @property
    def backpressure_metrics(self) -> BackpressureMetrics:
        return backpressure_metrics 