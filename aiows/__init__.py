"""
aiows - Modern WebSocket framework inspired by aiogram
"""

from .server import WebSocketServer
from .router import Router
from .websocket import WebSocket
from .dispatcher import MessageDispatcher
from .types import BaseMessage, ChatMessage, JoinRoomMessage, GameActionMessage
from .exceptions import AiowsException, ConnectionError, MessageValidationError
from .middleware import BaseMiddleware, AuthMiddleware, LoggingMiddleware, RateLimitingMiddleware, ConnectionLimiterMiddleware
from .health import (
    HealthStatus, HealthCheck, HealthChecker,
    ConnectionsHealthCheck, MiddlewareHealthCheck, MemoryHealthCheck, SystemHealthCheck,
    setup_health_checks, get_health_checker
)

__all__ = [
    # Core components
    "WebSocketServer",
    "Router", 
    "WebSocket",
    "MessageDispatcher",
    
    # Message types
    "BaseMessage",
    "ChatMessage",
    "JoinRoomMessage", 
    "GameActionMessage",
    
    # Exceptions
    "AiowsException",
    "ConnectionError",
    "MessageValidationError",
    
    # Middleware
    "BaseMiddleware",
    "AuthMiddleware",
    "LoggingMiddleware", 
    "RateLimitingMiddleware",
    "ConnectionLimiterMiddleware",
    
    # Health monitoring
    "HealthStatus",
    "HealthCheck", 
    "HealthChecker",
    "ConnectionsHealthCheck",
    "MiddlewareHealthCheck",
    "MemoryHealthCheck",
    "SystemHealthCheck",
    "setup_health_checks",
    "get_health_checker"
]

__version__ = "0.1.1" 