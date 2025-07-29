"""
Exception classes for aiows framework

This module provides a comprehensive error handling system with categorization,
context preservation, and consistent logging across all framework components.

Error Categories:
    FATAL: System resource issues that require immediate stop (MemoryError, OSError)
    RECOVERABLE: Temporary failures that can be retried (TimeoutError, asyncio.TimeoutError)
    CLIENT_ERROR: Bad input from client (MessageValidationError, MessageSizeError)
    SERVER_ERROR: Internal framework issues (MiddlewareError, ConnectionError)

Usage:
    from aiows.exceptions import ErrorCategorizer, ErrorContext, ErrorCategory
    
    # Categorize any exception
    category = ErrorCategorizer.categorize_exception(exception)
    
    # Create error context for logging
    context = ErrorContext(operation="send_message", component="websocket")
    
    # Determine if middleware chain should stop
    should_stop = ErrorCategorizer.should_stop_middleware_chain(exception, middleware_name)
"""

from enum import Enum
from typing import Dict, Any, Optional


class ErrorCategory(Enum):
    """
    Error categories for consistent error handling across the framework.
    
    Categories:
        FATAL: System resource issues that require immediate stop
               Examples: MemoryError, OSError
               Behavior: Stop all processing, use critical logging
               
        RECOVERABLE: Temporary failures that can be retried  
                    Examples: TimeoutError, asyncio.TimeoutError
                    Behavior: Stop current operation, allow retry, use info logging
                    
        CLIENT_ERROR: Bad input from client
                     Examples: MessageValidationError, MessageSizeError
                     Behavior: Stop middleware chain, respond to client, use warning logging
                     
        SERVER_ERROR: Internal framework issues
                     Examples: MiddlewareError, ConnectionError
                     Behavior: Log error, attempt graceful degradation, use error logging
    """
    FATAL = "fatal"
    RECOVERABLE = "recoverable"
    CLIENT_ERROR = "client_error"
    SERVER_ERROR = "server_error"


class ErrorContext:
    """
    Context information for error handling and logging.
    
    Provides structured context that is preserved through the entire error handling
    call chain, enabling detailed debugging and monitoring.
    
    Attributes:
        operation: The operation being performed when the error occurred
        component: The framework component where the error occurred  
        error_id: Unique identifier for this error instance
        additional_context: Additional context-specific information
        
    Example:
        context = ErrorContext(
            operation="message_parsing",
            component="dispatcher", 
            additional_context={
                'message_type': 'chat',
                'user_id': 'user123',
                'message_size': 1024
            }
        )
    """
    
    def __init__(self, 
                 operation: str,
                 component: str,
                 error_id: Optional[str] = None,
                 additional_context: Optional[Dict[str, Any]] = None):
        """
        Initialize error context.
        
        Args:
            operation: The operation being performed (e.g., "send_json", "middleware_connect")
            component: The component where error occurred (e.g., "websocket", "dispatcher")
            error_id: Optional custom error ID, auto-generated if not provided
            additional_context: Additional context data for debugging
        """
        self.operation = operation
        self.component = component
        self.error_id = error_id or self._generate_error_id()
        self.additional_context = additional_context or {}
        
    def _generate_error_id(self) -> str:
        """Generate a short, unique error ID for tracking."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary for structured logging.
        
        Returns:
            Dictionary containing all context information
        """
        return {
            'operation': self.operation,
            'component': self.component,
            'error_id': self.error_id,
            **self.additional_context
        }


class CategorizedError:
    """
    Mixin for errors with category and context.
    
    This is a base class for creating new exception types that automatically
    include category and context information.
    """
    
    def __init__(self, message: str, category: ErrorCategory, context: Optional[ErrorContext] = None):
        """
        Initialize categorized error.
        
        Args:
            message: Error message
            category: Error category
            context: Optional error context
        """
        self.category = category
        self.context = context
        super().__init__(message)


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


class MessageSizeError(AiowsException):
    """Exception raised when message size exceeds limit"""
    
    def __init__(self, message: str = "Message size limit exceeded"):
        super().__init__(message)


class RouterError(AiowsException):
    """Exception raised for routing errors"""
    
    def __init__(self, message: str = "Routing error occurred"):
        super().__init__(message)


class MiddlewareError(AiowsException):
    """Exception raised for middleware processing errors"""
    
    def __init__(self, message: str = "Middleware error occurred"):
        super().__init__(message)


class ErrorCategorizer:
    """
    Utility class for categorizing exceptions into error categories.
    
    This class provides the central logic for determining how different types
    of exceptions should be handled across the framework. It ensures consistent
    behavior for error categorization, logging levels, and middleware chain
    management.
    
    Methods:
        categorize_exception: Determine the category of an exception
        should_stop_middleware_chain: Determine if middleware chain should stop
        get_log_level: Get appropriate log level for an exception
        
    Example:
        category = ErrorCategorizer.categorize_exception(exception)
        log_level = ErrorCategorizer.get_log_level(exception)
        should_stop = ErrorCategorizer.should_stop_middleware_chain(exception)
    """
    
    _CATEGORIZATION_RULES = {
        MemoryError: ErrorCategory.FATAL,
        OSError: ErrorCategory.FATAL,
        MessageValidationError: ErrorCategory.CLIENT_ERROR,
        MessageSizeError: ErrorCategory.CLIENT_ERROR,
        MiddlewareError: ErrorCategory.SERVER_ERROR,
        RouterError: ErrorCategory.SERVER_ERROR,
        ConnectionError: ErrorCategory.SERVER_ERROR,
        TimeoutError: ErrorCategory.RECOVERABLE,
    }
    
    @classmethod
    def categorize_exception(cls, exception: Exception) -> ErrorCategory:
        """
        Categorize an exception into an error category.
        
        This method determines how the framework should handle a specific exception
        by categorizing it into one of the four error categories.
        
        Args:
            exception: The exception to categorize
            
        Returns:
            ErrorCategory for the exception
            
        Example:
            memory_error = MemoryError("Out of memory")
            category = ErrorCategorizer.categorize_exception(memory_error)
            assert category == ErrorCategory.FATAL
        """
        if hasattr(exception, 'category') and isinstance(exception.category, ErrorCategory):
            return exception.category
        
        exception_type = type(exception)
        if exception_type in cls._CATEGORIZATION_RULES:
            return cls._CATEGORIZATION_RULES[exception_type]
        
        for error_type, category in cls._CATEGORIZATION_RULES.items():
            if isinstance(exception, error_type):
                return category
        
        if exception_type.__name__ in ['TimeoutError', 'CancelledError']:
            if 'asyncio' in str(exception_type.__module__):
                return ErrorCategory.RECOVERABLE
        
        return ErrorCategory.SERVER_ERROR
    
    @classmethod
    def should_stop_middleware_chain(cls, exception: Exception, middleware_name: str = "") -> bool:
        """
        Determine if an exception should stop the middleware chain.
        
        This method implements the logic for deciding whether middleware processing
        should continue or stop based on the type of exception and the context.
        
        Args:
            exception: The exception to evaluate
            middleware_name: Name of the middleware for special handling
            
        Returns:
            True if middleware chain should stop, False if it should continue
            
        Logic:
            - FATAL errors always stop everything
            - Connection errors stop the chain  
            - Timeout/cancellation errors stop the chain
            - CLIENT_ERROR in message processing stops the chain
            - Critical middleware (auth, security) errors stop the chain
            - Other errors allow continuation for graceful degradation
            
        Example:
            memory_error = MemoryError("Out of memory")
            should_stop = ErrorCategorizer.should_stop_middleware_chain(memory_error)
            assert should_stop == True
            
            regular_error = MiddlewareError("Regular error") 
            should_stop = ErrorCategorizer.should_stop_middleware_chain(regular_error, "LoggingMiddleware")
            assert should_stop == False
        """
        category = cls.categorize_exception(exception)
        
        if category == ErrorCategory.FATAL:
            return True
        
        if isinstance(exception, ConnectionError):
            return True
        
        if category == ErrorCategory.RECOVERABLE and isinstance(exception, (TimeoutError,)):
            return True
        
        if isinstance(exception, MiddlewareError):
            middleware_lower = middleware_name.lower()
            if any(keyword in middleware_lower for keyword in ['auth', 'security']):
                return True
        
        if category == ErrorCategory.CLIENT_ERROR:
            return True
        
        return False
    
    @classmethod
    def get_log_level(cls, exception: Exception) -> str:
        """
        Get appropriate log level for an exception.
        
        This method ensures consistent logging levels across the framework
        based on error categories.
        
        Args:
            exception: The exception to evaluate
            
        Returns:
            Log level string ('debug', 'info', 'warning', 'error', 'critical')
            
        Mapping:
            FATAL -> critical: System-critical issues requiring immediate attention
            SERVER_ERROR -> error: Internal framework issues needing investigation  
            CLIENT_ERROR -> warning: Bad client input, expected in normal operation
            RECOVERABLE -> info: Temporary issues, normal retry scenarios
            
        Example:
            memory_error = MemoryError("Out of memory")
            log_level = ErrorCategorizer.get_log_level(memory_error)
            assert log_level == 'critical'
            
            validation_error = MessageValidationError("Invalid format")
            log_level = ErrorCategorizer.get_log_level(validation_error)  
            assert log_level == 'warning'
        """
        category = cls.categorize_exception(exception)
        
        if category == ErrorCategory.FATAL:
            return 'critical'
        elif category == ErrorCategory.SERVER_ERROR:
            return 'error'
        elif category == ErrorCategory.CLIENT_ERROR:
            return 'warning'
        elif category == ErrorCategory.RECOVERABLE:
            return 'info'
        else:
            return 'error' 