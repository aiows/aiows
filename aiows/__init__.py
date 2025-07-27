"""
aiows - Modern WebSocket framework inspired by aiogram
"""

from .server import WebSocketServer
from .router import Router
from .websocket import WebSocket
from .dispatcher import MessageDispatcher
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage
from .exceptions import AiowsException, ConnectionError, MessageValidationError
from .middleware import BaseMiddleware, AuthMiddleware, LoggingMiddleware, RateLimitingMiddleware

__all__ = [
    "WebSocketServer",
    "Router", 
    "WebSocket",
    "MessageDispatcher",
    "BaseMessage",
    "ChatMessage",
    "JoinRoomMessage", 
    "GameActionMessage",
    "AiowsException",
    "ConnectionError",
    "MessageValidationError",
    "BaseMiddleware",
    "AuthMiddleware",
    "LoggingMiddleware", 
    "RateLimitingMiddleware"
]

__version__ = "0.1.0" 