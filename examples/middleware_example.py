"""
Example of using middleware in aiows framework

This example demonstrates:
- Adding middleware to server and router
- Using AuthMiddleware for user authentication
- Using LoggingMiddleware for request logging
- Working with user context

To test this example:
1. Run the server: python examples/middleware_example.py
2. Connect via WebSocket to ws://localhost:8000
3. Send authentication with token in query: ws://localhost:8000?token=user123secret_key
4. Send messages to see middleware in action

Example messages:
{"type": "chat", "text": "Hello world!"}
{"type": "ping"}
"""

import asyncio
import logging
from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage,
    AuthMiddleware,
    LoggingMiddleware,
    RateLimitingMiddleware
)

# Configure logging to see middleware output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create router for handling messages
router = Router()

@router.connect()
async def handle_connect(websocket: WebSocket):
    """Handle user connection"""
    user_id = websocket.context.get('user_id', 'anonymous')
    print(f"User {user_id} connected successfully!")
    
    # Send welcome message
    await websocket.send_json({
        "type": "welcome",
        "message": f"Welcome, {user_id}!",
        "authenticated": websocket.context.get('authenticated', False)
    })

@router.message("chat")
async def handle_chat_message(websocket: WebSocket, message: BaseMessage):
    """Handle chat messages"""
    user_id = websocket.context.get('user_id', 'anonymous')
    
    # Access rate limit info added by middleware
    rate_limit = websocket.context.get('rate_limit', {})
    remaining = rate_limit.get('remaining_messages', 'unknown')
    
    print(f"Chat message from {user_id}: {message.dict()}")
    print(f"Remaining messages: {remaining}")
    
    # Echo message back with user info
    await websocket.send_json({
        "type": "chat_response", 
        "from_user": user_id,
        "original_message": message.dict(),
        "remaining_messages": remaining
    })

@router.message("ping")
async def handle_ping(websocket: WebSocket, message: BaseMessage):
    """Handle ping messages"""
    user_id = websocket.context.get('user_id', 'anonymous')
    
    await websocket.send_json({
        "type": "pong",
        "from_user": user_id,
        "timestamp": message.dict().get('timestamp', 'unknown')
    })

@router.message()  # Handle all message types
async def handle_unknown_message(websocket: WebSocket, message: BaseMessage):
    """Handle unknown message types"""
    user_id = websocket.context.get('user_id', 'anonymous')
    
    await websocket.send_json({
        "type": "error",
        "message": f"Unknown message type: {message.dict().get('type', 'none')}",
        "from_user": user_id
    })

@router.disconnect()
async def handle_disconnect(websocket: WebSocket, reason: str):
    """Handle user disconnection"""
    user_id = websocket.context.get('user_id', 'anonymous')
    print(f"User {user_id} disconnected: {reason}")

def create_server():
    """Create and configure WebSocket server with middleware"""
    server = WebSocketServer()
    
    # Add global middleware (applies to all connections)
    
    # 1. Logging middleware - logs all events
    logging_middleware = LoggingMiddleware("aiows.server")
    server.add_middleware(logging_middleware)
    
    # 2. Authentication middleware - validates tokens
    # Token format: "user123secret_key" (user_id + secret_key)
    auth_middleware = AuthMiddleware("secret_key")
    server.add_middleware(auth_middleware)
    
    # 3. Rate limiting middleware - limits messages per minute
    rate_limit_middleware = RateLimitingMiddleware(max_messages_per_minute=30)
    server.add_middleware(rate_limit_middleware)
    
    # You can also add middleware to specific routers
    # router.add_middleware(some_middleware)
    
    # Include router to server
    server.include_router(router)
    
    return server

def main():
    """Main function to run the server"""
    print("Starting aiows server with middleware example...")
    print("Middleware order: Logging -> Auth -> RateLimit -> Handlers")
    print()
    print("Test the server with:")
    print("1. Valid token: ws://localhost:8000?token=user123secret_key")
    print("2. Invalid token: ws://localhost:8000?token=invalid_token")
    print("3. No token: ws://localhost:8000")
    print()
    print("Send messages like:")
    print('{"type": "chat", "text": "Hello!"}')
    print('{"type": "ping", "timestamp": "2024-01-01"}')
    print()
    
    server = create_server()
    
    try:
        server.run(host="localhost", port=8000)
    except KeyboardInterrupt:
        print("\nShutting down server...")

if __name__ == "__main__":
    main() 