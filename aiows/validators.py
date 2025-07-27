"""
Comprehensive input validation system for aiows
Provides protection against SQL injection, XSS, command injection, path traversal and other attacks
"""

import re
import json
from typing import Any, List, Set
from pydantic import validator


class SecurityLimits:
    MAX_TEXT_LENGTH = 10000
    MAX_USERNAME_LENGTH = 50
    MAX_ROOM_ID_LENGTH = 100
    MAX_ACTION_LENGTH = 50
    MAX_JSON_DEPTH = 10
    MAX_JSON_SIZE = 1048576  # 1MB
    MAX_ARRAY_LENGTH = 1000
    MAX_OBJECT_KEYS = 100


class SecurityPatterns:
    SQL_INJECTION_PATTERNS = [
        r"(?i)(union\s+select\s+|select\s+.*\s+from\s+|insert\s+into\s+|update\s+.*\s+set\s+|delete\s+from\s+)",
        r"(?i)(drop\s+table\s+|alter\s+table\s+|create\s+table\s+)",
        r"(?i)(exec\s*\(|execute\s*\(|sp_executesql)",
        r"(?i)(\-\-[^\n]*|\/\*.*?\*\/)",
        r"(?i)(\s+(or|and)\s+1\s*=\s*1\s*)",
        r"(?i)(0x[0-9a-f]+|char\s*\(|ascii\s*\()",
        r"[';]\s*(\-\-|drop|delete|insert|update|union|select)",
        r"(?i)(\'\s*(or|and|union|select|drop|delete|insert|update)\s*)",
    ]
    
    XSS_PATTERNS = [
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)<iframe[^>]*>.*?</iframe>",
        r"(?i)<object[^>]*>.*?</object>",
        r"(?i)<embed[^>]*>.*?</embed>",
        r"(?i)<link[^>]*>",
        r"(?i)<meta[^>]*>",
        r"(?i)javascript:",
        r"(?i)vbscript:",
        r"(?i)data:text/html",
        r"(?i)on(load|click|error|focus|blur|change|submit|keypress|keydown|keyup|mouseover|mouseout)\s*=",
        r"(?i)expression\s*\(",
        r"(?i)<\s*\/?\s*(script|iframe|object|embed|link|meta|style|form|input|button|textarea|select|option)",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$(){}]",
        r"(?i)(bash|sh|cmd|powershell|pwsh)",
        r"(?i)(wget|curl|nc|netcat)",
        r"(?i)(rm\s|del\s|format\s)",
        r"(?i)(cat\s|type\s|more\s|less\s)",
        r"(?i)(echo\s|print\s)",
        r"(?i)(chmod\s|chown\s|sudo\s)",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\.\/",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"\.\.%2f",
        r"\.\.%5c",
        r"%252e%252e%252f",
        r"(?i)(\/etc\/|\/bin\/|\/usr\/|\/var\/|\/tmp\/|\/home\/)",
        r"(?i)(c:\\|d:\\|\\windows\\|\\system32\\)",
        r"\\\\[^\\]+\\[^\\]+",
        r"\.{4,}[\/\\]",
    ]
    
    DANGEROUS_PATTERNS = [
        r"(?i)(eval\s*\(|function\s*\()",
        r"(?i)(import\s+|require\s*\(|include\s*\()",
        r"(?i)(file_get_contents|readfile|fopen|fread)",
        r"(?i)(system\s*\(|shell_exec\s*\(|exec\s*\(|passthru\s*\()",
        r"(?i)(base64_decode|urldecode|rawurldecode)",
    ]


class SecurityValidator:
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        for pattern in SecurityPatterns.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def check_xss(value: str) -> bool:
        for pattern in SecurityPatterns.XSS_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def check_command_injection(value: str) -> bool:
        for pattern in SecurityPatterns.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def check_path_traversal(value: str) -> bool:
        for pattern in SecurityPatterns.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def check_dangerous_patterns(value: str) -> bool:
        for pattern in SecurityPatterns.DANGEROUS_PATTERNS:
            if re.search(pattern, value):
                return True
        return False
    
    @staticmethod
    def is_safe_string(value: str) -> bool:
        return not (
            SecurityValidator.check_sql_injection(value) or
            SecurityValidator.check_xss(value) or
            SecurityValidator.check_command_injection(value) or
            SecurityValidator.check_path_traversal(value) or
            SecurityValidator.check_dangerous_patterns(value)
        )


class Sanitizer:
    REMOVE_CHARS = set(['<', '>', '"', "'", '&', '\x00', '\r'])
    
    ESCAPE_MAP = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    
    @staticmethod
    def sanitize_text(value: str) -> str:
        if not isinstance(value, str):
            return str(value)
        
        sanitized = ''.join(char for char in value if char not in Sanitizer.REMOVE_CHARS)
        sanitized = ' '.join(sanitized.split())
        
        return sanitized
    
    @staticmethod
    def sanitize_identifier(value: str) -> str:
        if not isinstance(value, str):
            return str(value)
        
        sanitized = ''.join(char for char in value if char not in Sanitizer.REMOVE_CHARS)
        sanitized = re.sub(r'[^a-zA-Z0-9_.-]', '', sanitized)
        sanitized = re.sub(r'^[.-]+', '', sanitized)
        
        return sanitized
    
    @staticmethod
    def sanitize_action(value: str) -> str:
        if not isinstance(value, str):
            return str(value)
        
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '', value)
        
        return sanitized


class JSONBombProtector:
    @staticmethod
    def check_json_bomb(data: Any, depth: int = 0) -> bool:
        if depth > SecurityLimits.MAX_JSON_DEPTH:
            return True
        
        if isinstance(data, dict):
            if len(data) > SecurityLimits.MAX_OBJECT_KEYS:
                return True
            for value in data.values():
                if JSONBombProtector.check_json_bomb(value, depth + 1):
                    return True
        
        elif isinstance(data, list):
            if len(data) > SecurityLimits.MAX_ARRAY_LENGTH:
                return True
            for item in data:
                if JSONBombProtector.check_json_bomb(item, depth + 1):
                    return True
        
        elif isinstance(data, str):
            if len(data) > SecurityLimits.MAX_TEXT_LENGTH:
                return True
        
        return False
    
    @staticmethod
    def validate_json_size(json_string: str) -> bool:
        return len(json_string.encode('utf-8')) <= SecurityLimits.MAX_JSON_SIZE


class WhitelistValidator:
    USERNAME_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-')
    ROOM_ID_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')
    ACTION_CHARS = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_')
    
    ALLOWED_ACTIONS = {
        'move', 'attack', 'defend', 'use_item', 'cast_spell', 
        'jump', 'run', 'walk', 'look', 'take', 'drop',
        'open', 'close', 'push', 'pull', 'activate'
    }
    
    @staticmethod
    def validate_username(value: str) -> bool:
        if not value or len(value) > SecurityLimits.MAX_USERNAME_LENGTH:
            return False
        return all(char in WhitelistValidator.USERNAME_CHARS for char in value)
    
    @staticmethod
    def validate_room_id(value: str) -> bool:
        if not value or len(value) > SecurityLimits.MAX_ROOM_ID_LENGTH:
            return False
        return all(char in WhitelistValidator.ROOM_ID_CHARS for char in value)
    
    @staticmethod
    def validate_action(value: str) -> bool:
        if not value or len(value) > SecurityLimits.MAX_ACTION_LENGTH:
            return False
        return (all(char in WhitelistValidator.ACTION_CHARS for char in value) and
                value.lower() in WhitelistValidator.ALLOWED_ACTIONS)


def validate_safe_text(cls, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Value must be a string")
    
    if len(value) > SecurityLimits.MAX_TEXT_LENGTH:
        raise ValueError(f"Text too long: maximum {SecurityLimits.MAX_TEXT_LENGTH} characters")
    
    if not SecurityValidator.is_safe_string(value):
        raise ValueError("Text contains dangerous patterns")
    
    return Sanitizer.sanitize_text(value)


def validate_username(cls, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Username must be a string")
    
    sanitized = Sanitizer.sanitize_identifier(value)
    
    if not WhitelistValidator.validate_username(sanitized):
        raise ValueError("Invalid username: contains forbidden characters or too long")
    
    if not sanitized.strip():
        raise ValueError("Username cannot be empty")
    
    return sanitized


def validate_room_id(cls, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Room ID must be a string")
    
    sanitized = Sanitizer.sanitize_identifier(value)
    
    if not WhitelistValidator.validate_room_id(sanitized):
        raise ValueError("Invalid room ID: contains forbidden characters or too long")
    
    if not sanitized.strip():
        raise ValueError("Room ID cannot be empty")
    
    return sanitized


def validate_game_action(cls, value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Action must be a string")
    
    sanitized = Sanitizer.sanitize_action(value)
    
    if not WhitelistValidator.validate_action(sanitized):
        raise ValueError("Invalid action: not in allowed actions list")
    
    return sanitized


def validate_user_id(cls, value) -> int:
    if isinstance(value, str):
        raise ValueError("User ID must be an integer, not a string")
    
    if isinstance(value, float):
        raise ValueError("User ID must be an integer, not a float")
    
    if not isinstance(value, int):
        raise ValueError("User ID must be an integer")
    
    if value < 1 or value > 2147483647:  # Max PostgreSQL integer
        raise ValueError("User ID must be between 1 and 2147483647")
    
    return value


def validate_coordinates(cls, value) -> tuple:
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        raise ValueError("Coordinates must be a tuple/list of 2 elements")
    
    x, y = value
    
    if not isinstance(x, int) or not isinstance(y, int):
        raise ValueError("Coordinates must be integers")
    
    if not (-10000 <= x <= 10000) or not (-10000 <= y <= 10000):
        raise ValueError("Coordinates out of allowed range")
    
    return tuple(value) 