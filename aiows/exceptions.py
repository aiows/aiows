"""
Exception classes for aiows
"""


class AiowsException(Exception):
    """Base exception class for aiows framework"""
    
    def __init__(self, message: str = "Aiows error occurred"):
        self.message = message
        super().__init__(self.message)


class ConnectionError(AiowsException):
    """Exception raised for WebSocket connection errors"""
    
    def __init__(self, message: str = "WebSocket connection error"):
        super().__init__(message)


class MessageValidationError(AiowsException):
    """Exception raised for message validation errors"""
    
    def __init__(self, message: str = "Message validation failed"):
        super().__init__(message)


class RouterError(AiowsException):
    """Exception raised for routing errors"""
    
    def __init__(self, message: str = "Routing error occurred"):
        super().__init__(message)


class MiddlewareError(AiowsException):
    """Exception raised for middleware processing errors"""
    
    def __init__(self, message: str = "Middleware error occurred"):
        super().__init__(message) 