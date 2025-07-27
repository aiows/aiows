"""
WebSocket connection wrapper
"""

import asyncio
import logging
from typing import Dict, Any
import json
from datetime import datetime
from .types import BaseMessage
from .exceptions import ConnectionError

logger = logging.getLogger(__name__)

# Default timeout for operations (in seconds)
DEFAULT_OPERATION_TIMEOUT = 30.0


class WebSocket:
    """WebSocket connection wrapper for aiows framework"""
    
    def __init__(self, websocket, operation_timeout: float = DEFAULT_OPERATION_TIMEOUT):
        """Initialize WebSocket wrapper
        
        Args:
            websocket: Standard websocket object
            operation_timeout: Timeout for WebSocket operations in seconds
        """
        self._websocket = websocket
        self.context: Dict[str, Any] = {}
        self._is_closed: bool = False
        self._lock = asyncio.Lock()  # Thread safety lock
        self._operation_timeout = operation_timeout
    
    async def send_json(self, data: dict) -> None:
        """Send JSON data through WebSocket
        
        Args:
            data: Dictionary to send as JSON
            
        Raises:
            ConnectionError: If connection is closed or send fails
        """
        async with self._lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Custom JSON encoder to handle datetime objects
                def json_serializer(obj):
                    if isinstance(obj, datetime):
                        return obj.isoformat()
                    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
                
                json_data = json.dumps(data, default=json_serializer)
                
                # Use timeout protection for send operation
                await asyncio.wait_for(
                    self._websocket.send(json_data),
                    timeout=self._operation_timeout
                )
            except asyncio.TimeoutError:
                # Mark as closed on timeout
                self._is_closed = True
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
            except Exception as e:
                # Mark as closed on any error
                self._is_closed = True
                raise ConnectionError(f"Failed to send JSON data: {str(e)}")
    
    async def send_message(self, message: BaseMessage) -> None:
        """Send BaseMessage through WebSocket
        
        Args:
            message: BaseMessage instance to send
            
        Raises:
            ConnectionError: If connection is closed or send fails
        """
        await self.send_json(message.dict())
    
    async def receive_json(self) -> dict:
        """Receive JSON data from WebSocket
        
        Returns:
            Dictionary with received data
            
        Raises:
            ConnectionError: If connection is closed or receive fails
        """
        async with self._lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Use timeout protection for receive operation
                raw_data = await asyncio.wait_for(
                    self._websocket.recv(),
                    timeout=self._operation_timeout
                )
                
                try:
                    return json.loads(raw_data)
                except json.JSONDecodeError as e:
                    raise ConnectionError(f"Invalid JSON received: {str(e)}")
            except asyncio.TimeoutError:
                # Mark as closed on timeout
                self._is_closed = True
                raise ConnectionError(f"Receive operation timed out after {self._operation_timeout} seconds")
            except Exception as e:
                # Mark as closed on any error
                self._is_closed = True
                raise ConnectionError(f"Failed to receive JSON data: {str(e)}")
    
    async def recv(self) -> str:
        """Receive raw data from WebSocket
        
        Returns:
            Raw string data received from WebSocket
            
        Raises:
            ConnectionError: If connection is closed or receive fails
        """
        async with self._lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Use timeout protection for receive operation
                return await asyncio.wait_for(
                    self._websocket.recv(),
                    timeout=self._operation_timeout
                )
            except asyncio.TimeoutError:
                # Mark as closed on timeout
                self._is_closed = True
                raise ConnectionError(f"Receive operation timed out after {self._operation_timeout} seconds")
            except Exception as e:
                # Mark as closed on any error
                self._is_closed = True
                raise ConnectionError(f"Failed to receive data: {str(e)}")
    
    async def send(self, data: str) -> None:
        """Send raw data through WebSocket
        
        Args:
            data: String data to send
            
        Raises:
            ConnectionError: If connection is closed or send fails
        """
        async with self._lock:
            if self._is_closed:
                raise ConnectionError("WebSocket connection is closed")
            
            try:
                # Use timeout protection for send operation
                await asyncio.wait_for(
                    self._websocket.send(data),
                    timeout=self._operation_timeout
                )
            except asyncio.TimeoutError:
                # Mark as closed on timeout
                self._is_closed = True
                raise ConnectionError(f"Send operation timed out after {self._operation_timeout} seconds")
            except Exception as e:
                # Mark as closed on any error
                self._is_closed = True
                raise ConnectionError(f"Failed to send data: {str(e)}")
    
    async def close(self, code: int = 1000, reason: str = "") -> None:
        """Close WebSocket connection
        
        Args:
            code: Close code (default: 1000)
            reason: Close reason (default: empty string)
            
        Note:
            This method is safe to call multiple times concurrently.
            Subsequent calls will be no-ops.
        """
        async with self._lock:
            # Check if already closed (atomic check)
            if self._is_closed:
                logger.debug("WebSocket connection already closed, ignoring close() call")
                return
            
            # Mark as closed immediately to prevent other operations
            self._is_closed = True
            
            try:
                # Use timeout protection for close operation
                await asyncio.wait_for(
                    self._websocket.close(code=code, reason=reason),
                    timeout=self._operation_timeout
                )
                logger.debug(f"WebSocket connection closed gracefully with code {code}")
            except asyncio.TimeoutError:
                logger.warning(f"WebSocket close operation timed out after {self._operation_timeout} seconds")
            except Exception as e:
                logger.debug(f"Error during WebSocket close: {str(e)}")
    
    @property
    def closed(self) -> bool:
        """Check if WebSocket connection is closed
        
        Returns:
            True if connection is closed, False otherwise
            
        Note:
            This property provides an atomic read of the closed state.
        """
        return self._is_closed
    
    @property  
    def is_closed(self) -> bool:
        """Check if WebSocket connection is closed (alias for backward compatibility)
        
        Returns:
            True if connection is closed, False otherwise
        """
        return self._is_closed
    
    def set_operation_timeout(self, timeout: float) -> None:
        """Set timeout for WebSocket operations
        
        Args:
            timeout: Timeout in seconds
        """
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        self._operation_timeout = timeout 