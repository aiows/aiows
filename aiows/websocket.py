"""
WebSocket connection wrapper
"""

import logging
from typing import Dict, Any
import json
from datetime import datetime
from .types import BaseMessage
from .exceptions import ConnectionError

logger = logging.getLogger(__name__)


class WebSocket:
    """WebSocket connection wrapper for aiows framework"""
    
    def __init__(self, websocket):
        """Initialize WebSocket wrapper
        
        Args:
            websocket: Standard websocket object
        """
        self._websocket = websocket
        self.context: Dict[str, Any] = {}
        self.is_closed: bool = False
    
    async def send_json(self, data: dict) -> None:
        """Send JSON data through WebSocket
        
        Args:
            data: Dictionary to send as JSON
            
        Raises:
            ConnectionError: If connection is closed or send fails
        """
        if self.is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        try:
            # Custom JSON encoder to handle datetime objects
            def json_serializer(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")
            
            json_data = json.dumps(data, default=json_serializer)
            await self._websocket.send(json_data)
        except Exception as e:
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
        if self.is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        try:
            raw_data = await self._websocket.recv()
            try:
                return json.loads(raw_data)
            except json.JSONDecodeError as e:
                raise ConnectionError(f"Invalid JSON received: {str(e)}")
        except Exception as e:
            self.is_closed = True
            raise ConnectionError(f"Failed to receive JSON data: {str(e)}")
    
    async def recv(self) -> str:
        """Receive raw data from WebSocket
        
        Returns:
            Raw string data received from WebSocket
            
        Raises:
            ConnectionError: If connection is closed or receive fails
        """
        if self.is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        try:
            return await self._websocket.recv()
        except Exception as e:
            self.is_closed = True
            raise ConnectionError(f"Failed to receive data: {str(e)}")
    
    async def send(self, data: str) -> None:
        """Send raw data through WebSocket
        
        Args:
            data: String data to send
            
        Raises:
            ConnectionError: If connection is closed or send fails
        """
        if self.is_closed:
            raise ConnectionError("WebSocket connection is closed")
        
        try:
            await self._websocket.send(data)
        except Exception as e:
            raise ConnectionError(f"Failed to send data: {str(e)}")
    
    async def close(self, code: int = 1000, reason: str = "") -> None:
        """Close WebSocket connection
        
        Args:
            code: Close code (default: 1000)
            reason: Close reason (default: empty string)
        """
        if not self.is_closed:
            try:
                await self._websocket.close(code=code, reason=reason)
                logger.debug(f"WebSocket connection closed gracefully with code {code}")
            except Exception as e:
                logger.debug(f"Error during WebSocket close: {str(e)}")
            finally:
                self.is_closed = True
    
    @property
    def closed(self) -> bool:
        """Check if WebSocket connection is closed
        
        Returns:
            True if connection is closed, False otherwise
        """
        return self.is_closed 