#!/usr/bin/env python3
"""
Secure chat example using aiows with SSL/TLS support (WSS)

Features demonstrated:
- WSS (WebSocket Secure) connections
- Self-signed certificates for development
- Custom SSL certificates for production
- Graceful shutdown with SSL
- Connection management over secure channels
"""

import logging
import ssl
import os

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

# Global server instance
server = None

@router.connect()
async def handle_connect(websocket: WebSocket):
    """Connection handler - send welcome message"""
    logger.info(f"🔒 Secure connection established from {websocket.remote_address}")
    
    # Send welcome message
    welcome_data = {
        "type": "chat",
        "text": "🔒 Welcome to SECURE chat! Your connection is encrypted with SSL/TLS.",
        "user_id": 0,
        "secure": True
    }
    await websocket.send_json(welcome_data)

@router.message("chat") 
async def handle_chat_message(websocket: WebSocket, message: ChatMessage):
    """Chat message handler - send echo response"""
    logger.info(f"🔒 Received secure message from user {message.user_id}: {message.text}")
    
    # Create response message (echo)
    response_data = {
        "type": "chat",
        "text": f"🔒🤖 Secure Echo: {message.text}",
        "user_id": 999,  # Bot ID
        "secure": True
    }
    await websocket.send_json(response_data)

@router.message("shutdown")
async def handle_shutdown_request(websocket: WebSocket, message):
    """Handle shutdown request from client (demo only)"""
    logger.info(f"🔒 Received secure shutdown request from user {message.get('user_id', 'unknown')}")
    
    # Notify client that shutdown is starting
    await websocket.send_json({
        "type": "shutdown_initiated",
        "message": "🔒 Secure server received shutdown request. Starting graceful shutdown in 3 seconds...",
        "timestamp": message.get("timestamp", "unknown"),
        "secure": True
    })
    
    # Import needed for delayed shutdown
    import asyncio
    
    # Schedule graceful shutdown after short delay
    async def delayed_shutdown():
        await asyncio.sleep(3)  # Give client time to receive the response
        logger.info("🔒 Starting secure graceful shutdown...")
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
        logger.info(f"🔒 Secure client disconnected due to graceful server shutdown")
    else:
        logger.info(f"🔒 Secure client disconnected. Reason: {reason}")

def create_server_with_ssl(ssl_mode: str = "development") -> WebSocketServer:
    """Create WebSocket server with SSL configuration
    
    Args:
        ssl_mode: "development", "custom", or "production"
    """
    if ssl_mode == "development":
        # Development mode with self-signed certificates
        logger.info("🔒 Creating server with self-signed SSL certificate...")
        
        server = WebSocketServer(
            cert_config={
                'common_name': 'localhost',
                'org_name': 'aiows Secure Chat Demo', 
                'country': 'US',
                'days': 365
            }
        )
        
        # Enable development SSL (auto-generates self-signed cert)
        server.enable_development_ssl()
        return server
        
    elif ssl_mode == "custom":
        # Custom certificates (provide your own files)
        cert_file = "server.crt"
        key_file = "server.key"
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            logger.info(f"🔒 Creating server with custom SSL certificates: {cert_file}, {key_file}")
            
            # Create SSL context manually
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(cert_file, key_file)
            
            server = WebSocketServer(ssl_context=ssl_context)
            return server
        else:
            logger.warning(f"❌ Custom certificate files not found: {cert_file}, {key_file}")
            logger.info("🔄 Falling back to development mode...")
            return create_server_with_ssl("development")
            
    elif ssl_mode == "production":
        # Production mode - requires proper certificates
        logger.info("🔒 Creating server for production SSL...")
        
        # You should provide proper production certificates
        cert_file = os.environ.get('SSL_CERT_FILE', '/etc/ssl/certs/server.crt')
        key_file = os.environ.get('SSL_KEY_FILE', '/etc/ssl/private/server.key')
        
        if os.path.exists(cert_file) and os.path.exists(key_file):
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(cert_file, key_file)
            
            server = WebSocketServer(
                ssl_context=ssl_context,
                is_production=True,
                require_ssl_in_production=True
            )
            return server
        else:
            logger.error(f"❌ Production certificates not found: {cert_file}, {key_file}")
            logger.info("💡 Set SSL_CERT_FILE and SSL_KEY_FILE environment variables")
            raise FileNotFoundError("Production SSL certificates required")
    
    else:
        raise ValueError(f"Unknown SSL mode: {ssl_mode}")

def main():
    """Main function - create and run secure server"""
    global server
    
    # Determine SSL mode from environment or default to development
    ssl_mode = os.environ.get('SSL_MODE', 'development')
    port = int(os.environ.get('PORT', 8443))  # Default HTTPS port
    
    logger.info("=" * 60)
    logger.info("🔒 aiows Secure Chat Server (WSS)")
    logger.info("=" * 60)
    
    try:
        # Create server with SSL
        server = create_server_with_ssl(ssl_mode)
        
        # Configure graceful shutdown (15 seconds timeout)
        server.set_shutdown_timeout(15.0)
        
        # Connect router to server
        server.include_router(router)
        
        # Display server information
        protocol = server.protocol  # Will be "wss" if SSL enabled
        logger.info(f"🔒 SSL Mode: {ssl_mode}")
        logger.info(f"🔗 Protocol: {protocol}://")
        logger.info(f"📡 Server URL: {protocol}://localhost:{port}")
        logger.info(f"🔧 Graceful shutdown timeout: {server._shutdown_timeout}s")
        
        if ssl_mode == "development":
            logger.warning("⚠️  Using self-signed certificate - browsers will show security warning")
            logger.info("💡 Accept the certificate warning to test the secure connection")
            
        logger.info("=" * 60)
        logger.info("🛑 Press Ctrl+C for graceful shutdown")
        logger.info("=" * 60)
        
        # Start secure server
        server.run(host="localhost", port=port)
        
    except FileNotFoundError as e:
        logger.error(f"❌ SSL certificate error: {e}")
        logger.info("💡 Try setting SSL_MODE=development for self-signed certificates")
    except KeyboardInterrupt:
        logger.info("👋 Secure server shutdown completed")
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        raise
    finally:
        logger.info("🔒 Secure server stopped")

if __name__ == "__main__":
    main() 