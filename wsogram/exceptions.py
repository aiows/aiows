"""
Exception classes for wsogram
"""


class WSogramException(Exception):
    """Base exception class for wsogram framework"""
    
    def __init__(self, message: str = "WSogram error occurred"):
        self.message = message
        super().__init__(self.message)


class ConnectionError(WSogramException):
    """Exception raised for WebSocket connection errors"""
    
    def __init__(self, message: str = "WebSocket connection error"):
        super().__init__(message)


class MessageValidationError(WSogramException):
    """Exception raised for message validation errors"""
    
    def __init__(self, message: str = "Message validation failed"):
        super().__init__(message)


class RouterError(WSogramException):
    """Exception raised for routing errors"""
    
    def __init__(self, message: str = "Routing error occurred"):
        super().__init__(message)


class MiddlewareError(WSogramException):
    """Exception raised for middleware processing errors"""
    
    def __init__(self, message: str = "Middleware error occurred"):
        super().__init__(message) 