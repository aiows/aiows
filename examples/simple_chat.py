"""
Simple chat example using wsogram
"""

# Import main wsogram classes
from wsogram import WebSocketServer, Router, ChatMessage, WebSocket


# Create router for handling events
router = Router()


@router.connect()
async def handle_connect(websocket: WebSocket):
    """Connection handler - send welcome message"""
    print(f"New connection!")
    
    # Send welcome message
    welcome_data = {
        "type": "chat",
        "text": "Welcome to chat!",
        "user_id": 0
    }
    await websocket.send_json(welcome_data)


@router.message("chat") 
async def handle_chat_message(websocket: WebSocket, message: ChatMessage):
    """Chat message handler - send echo response"""
    print(f"Received message from user {message.user_id}: {message.text}")
    
    # Create response message (echo)
    response_data = {
        "type": "chat",
        "text": f"Echo: {message.text}",
        "user_id": 999  # Bot ID
    }
    await websocket.send_json(response_data)


@router.disconnect()
async def handle_disconnect(websocket: WebSocket, reason: str):
    """Disconnect handler - log the event"""
    print(f"User disconnected. Reason: {reason}")


def main():
    """Main function - create and run server"""
    # Create server
    server = WebSocketServer()
    
    # Connect router to server
    server.include_router(router)
    
    # Run server on localhost:8000
    print("Starting chat server...")
    print("Connect via WebSocket at ws://localhost:8000")
    server.run(host="localhost", port=8000)


if __name__ == "__main__":
    main()