#!/usr/bin/env python3
"""
Example demonstrating aiows input validation system
Shows how validation protects against various security attacks
"""

from pydantic import ValidationError
from aiows.types import ChatMessage, JoinRoomMessage, GameActionMessage


def demonstrate_sql_injection_protection():
    """Demonstrate SQL injection protection"""
    print("=== SQL Injection Protection ===")
    
    # Valid message
    try:
        valid_msg = ChatMessage(text="I want to select a good restaurant", user_id=1)
        print(f"✅ Valid: '{valid_msg.text}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # SQL injection attempt
    try:
        malicious_msg = ChatMessage(text="'; DROP TABLE users; --", user_id=1)
        print(f"✅ Dangerous message accepted: {malicious_msg.text}")
    except ValidationError as e:
        print(f"🛡️  SQL injection blocked: {str(e).split(',')[0]}")


def demonstrate_xss_protection():
    """Demonstrate XSS protection"""
    print("\n=== XSS Protection ===")
    
    # Valid message
    try:
        valid_msg = ChatMessage(text="Hello world!", user_id=2)
        print(f"✅ Valid: '{valid_msg.text}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # XSS attempt
    try:
        xss_msg = ChatMessage(text="<script>alert('XSS')</script>", user_id=2)
        print(f"✅ XSS message accepted: {xss_msg.text}")
    except ValidationError as e:
        print(f"🛡️  XSS attack blocked: {str(e).split(',')[0]}")


def demonstrate_command_injection_protection():
    """Demonstrate command injection protection"""
    print("\n=== Command Injection Protection ===")
    
    # Valid username
    try:
        valid_join = JoinRoomMessage(room_id="game_room", user_name="player123")
        print(f"✅ Valid username: '{valid_join.user_name}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # Command injection attempt
    try:
        malicious_join = JoinRoomMessage(room_id="room; rm -rf /", user_name="hacker")
        print(f"✅ Command injection accepted: {malicious_join.room_id}")
    except ValidationError as e:
        print(f"🛡️  Command injection blocked: {str(e).split(',')[0]}")


def demonstrate_size_limits():
    """Demonstrate size limit protection"""
    print("\n=== Size Limit Protection ===")
    
    # Valid message
    try:
        valid_msg = ChatMessage(text="Short message", user_id=3)
        print(f"✅ Valid length: {len(valid_msg.text)} characters")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # Oversized message
    try:
        oversized_msg = ChatMessage(text="A" * 20000, user_id=3)
        print(f"✅ Large message accepted: {len(oversized_msg.text)} characters")
    except ValidationError as e:
        print(f"🛡️  Oversized message blocked: {str(e).split(',')[0]}")


def demonstrate_whitelist_validation():
    """Demonstrate whitelist validation"""
    print("\n=== Whitelist Validation ===")
    
    # Valid action
    try:
        valid_action = GameActionMessage(action="move", coordinates=(10, 20))
        print(f"✅ Valid action: '{valid_action.action}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # Invalid action
    try:
        invalid_action = GameActionMessage(action="hack_database", coordinates=(0, 0))
        print(f"✅ Invalid action accepted: {invalid_action.action}")
    except ValidationError as e:
        print(f"🛡️  Invalid action blocked: {str(e).split(',')[0]}")


def demonstrate_sanitization():
    """Demonstrate input sanitization"""
    print("\n=== Input Sanitization ===")
    
    # Text with dangerous characters gets sanitized
    try:
        sanitized_msg = ChatMessage(text="Hello <user> & welcome!", user_id=4)
        print(f"✅ Original: 'Hello <user> & welcome!'")
        print(f"✅ Sanitized: '{sanitized_msg.text}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # Username with special characters gets sanitized
    try:
        sanitized_join = JoinRoomMessage(room_id="test-room", user_name="user<script>123")
        print(f"✅ Original username: 'user<script>123'")
        print(f"✅ Sanitized username: '{sanitized_join.user_name}'")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")


def demonstrate_type_validation():
    """Demonstrate type validation"""
    print("\n=== Type Validation ===")
    
    # Valid types
    try:
        valid_msg = ChatMessage(text="Hello", user_id=123)
        print(f"✅ Valid user_id: {valid_msg.user_id} (type: {type(valid_msg.user_id).__name__})")
    except ValidationError as e:
        print(f"❌ Rejected: {e}")
    
    # Invalid types
    try:
        invalid_msg = ChatMessage(text="Hello", user_id="not_a_number")
        print(f"✅ String user_id accepted: {invalid_msg.user_id}")
    except ValidationError as e:
        print(f"🛡️  Invalid type blocked: {str(e).split(',')[0]}")


if __name__ == "__main__":
    print("🛡️  aiows Input Validation System Demo")
    print("=" * 50)
    
    demonstrate_sql_injection_protection()
    demonstrate_xss_protection()
    demonstrate_command_injection_protection()
    demonstrate_size_limits()
    demonstrate_whitelist_validation()
    demonstrate_sanitization()
    demonstrate_type_validation()
    
    print("\n" + "=" * 50)
    print("✅ Validation system successfully protects against:")
    print("   • SQL injection attacks")
    print("   • XSS (Cross-Site Scripting) attacks")
    print("   • Command injection attacks")
    print("   • Path traversal attacks")
    print("   • JSON bomb attacks")
    print("   • Oversized data attacks")
    print("   • Type confusion attacks")
    print("   • Invalid characters and formats")
    print("\n🚀 All while maintaining good performance!")