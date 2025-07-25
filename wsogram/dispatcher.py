"""
Event dispatcher implementation
"""

from .router import Router
from .websocket import WebSocket  
from .types import BaseMessage
from .exceptions import MessageValidationError


class MessageDispatcher:
    """Dispatcher for handling WebSocket events and messages"""
    
    def __init__(self, router: Router):
        """Initialize MessageDispatcher with router
        
        Args:
            router: Router instance containing handlers
        """
        self.router = router
    
    async def dispatch_connect(self, websocket: WebSocket) -> None:
        """Handle WebSocket connection event
        
        Args:
            websocket: WebSocket connection instance
        """
        for handler in self.router._connect_handlers:
            try:
                await handler(websocket)
            except Exception as e:
                print(f"Error in connect handler: {str(e)}")
    
    async def dispatch_disconnect(self, websocket: WebSocket, reason: str) -> None:
        """Handle WebSocket disconnection event
        
        Args:
            websocket: WebSocket connection instance
            reason: Disconnection reason
        """
        for handler in self.router._disconnect_handlers:
            try:
                await handler(websocket, reason)
            except Exception as e:
                print(f"Error in disconnect handler: {str(e)}")
    
    async def dispatch_message(self, websocket: WebSocket, message_data: dict) -> None:
        """Handle WebSocket message event
        
        Args:
            websocket: WebSocket connection instance
            message_data: Raw message data as dictionary
        """
        try:
            # Try to create BaseMessage from message_data
            message = BaseMessage(**message_data)
        except Exception as e:
            raise MessageValidationError(f"Failed to parse message: {str(e)}")
        
        # Find suitable handler by message type
        suitable_handler = None
        message_type = message_data.get('type')
        
        for handler_info in self.router._message_handlers:
            handler_message_type = handler_info.get('message_type')
            
            # Match by message type or universal handler (None)
            if handler_message_type is None or handler_message_type == message_type:
                suitable_handler = handler_info.get('handler')
                break
        
        # Call first found handler
        if suitable_handler:
            try:
                await suitable_handler(websocket, message)
            except Exception as e:
                print(f"Error in message handler: {str(e)}")
        else:
            print(f"No handler found for message type: {message_type}") 