"""
WSogram - Modern WebSocket framework inspired by aiogram
"""

from .server import WebSocketServer
from .router import Router
from .websocket import WebSocket
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage
from .exceptions import WSogramException, ConnectionError, MessageValidationError

__all__ = [
    "WebSocketServer",
    "Router", 
    "WebSocket",
    "BaseMessage",
    "ChatMessage",
    "JoinRoomMessage", 
    "GameActionMessage",
    "WSogramException",
    "ConnectionError",
    "MessageValidationError"
]

__version__ = "0.1.0" 