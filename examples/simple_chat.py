"""
Simple chat example using aiows with graceful shutdown support

Features demonstrated:
- Basic WebSocket connection handling
- Message routing and validation
- Graceful shutdown with Ctrl+C
- Connection management
"""

import logging

# Import main aiows classes
from aiows import WebSocketServer, Router, ChatMessage, WebSocket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create router for handling events
router = Router()

# Global server instance (will be set in main)
server = None


@router.connect()
async def handle_connect(websocket: WebSocket):
    """Connection handler - send welcome message"""
    logger.info(f"New client connected from {websocket.remote_address}")
    
    # Send welcome message
    welcome_data = {
        "type": "chat",
        "text": "Welcome to the chat! Type any message to get an echo response.",
        "user_id": 0
    }
    await websocket.send_json(welcome_data)


@router.message("chat") 
async def handle_chat_message(websocket: WebSocket, message: ChatMessage):
    """Chat message handler - send echo response"""
    logger.info(f"Received message from user {message.user_id}: {message.text}")
    
    # Create response message (echo)
    response_data = {
        "type": "chat",
        "text": f"🤖 Echo: {message.text}",
        "user_id": 999  # Bot ID
    }
    await websocket.send_json(response_data)


@router.message("shutdown")
async def handle_shutdown_request(websocket: WebSocket, message):
    """Handle shutdown request from client (demo only)"""
    logger.info(f"Received shutdown request from user {message.get('user_id', 'unknown')}")
    
    # Notify client that shutdown is starting
    await websocket.send_json({
        "type": "shutdown_initiated",
        "message": "Server received shutdown request. Starting graceful shutdown in 3 seconds...",
        "timestamp": message.get("timestamp", "unknown")
    })
    
    # Import needed for delayed shutdown
    import asyncio
    
    # Schedule graceful shutdown after short delay
    async def delayed_shutdown():
        await asyncio.sleep(3)  # Give client time to receive the response
        logger.info("Starting graceful shutdown...")
        if server:
            await server.shutdown(timeout=10.0)
        else:
            logger.error("Server instance not available for shutdown")
    
    # Start shutdown task
    asyncio.create_task(delayed_shutdown())


@router.disconnect()
async def handle_disconnect(websocket: WebSocket, reason: str):
    """Disconnect handler - log the event"""
    if reason == "Server shutdown":
        logger.info(f"Client disconnected due to graceful server shutdown")
    else:
        logger.info(f"Client disconnected. Reason: {reason}")


def main():
    """Main function - create and run server with graceful shutdown"""
    global server
    
    # Create server
    server = WebSocketServer()
    
    # Configure graceful shutdown (15 seconds timeout)
    server.set_shutdown_timeout(15.0)
    
    # Connect router to server
    server.include_router(router)
    
    # Run server on localhost:8000
    logger.info("=" * 50)
    logger.info("🚀 Starting chat server with graceful shutdown...")
    logger.info("📡 Connect via WebSocket at ws://localhost:8000")
    logger.info("🛑 Press Ctrl+C for graceful shutdown")
    logger.info("=" * 50)
    
    try:
        server.run(host="localhost", port=8000)
    except KeyboardInterrupt:
        logger.info("👋 Server shutdown completed")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
    finally:
        logger.info("Server stopped")


if __name__ == "__main__":
    main()