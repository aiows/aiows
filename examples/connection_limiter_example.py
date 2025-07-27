"""
Example of using ConnectionLimiterMiddleware in aiows framework

This example demonstrates:
- Protection against connection flooding attacks
- Rate limiting of new connections using sliding window
- IP-based connection limits
- Whitelist for trusted IPs
- Real-time statistics monitoring
- Integration with other middleware

To test this example:
1. Run the server: python examples/connection_limiter_example.py
2. Connect multiple WebSocket clients to ws://localhost:8000
3. Try rapid connections to see rate limiting in action
4. Connect to ws://localhost:8000/stats to see live statistics

Trusted IPs (bypass all limits):
- 127.0.0.1 (localhost)
- 192.168.1.100 (example trusted IP)

Rate limits:
- Max 3 concurrent connections per IP
- Max 10 new connections per minute per IP
- Sliding window of 60 seconds

Test scenarios:
1. Normal usage: Connect 1-2 clients normally - should work fine
2. Connection limit: Try to open 4+ connections from same IP - 4th+ should be rejected
3. Rate limiting: Open/close connections rapidly - should get rate limited
4. Trusted IP: Change your IP to 192.168.1.100 in code - should bypass limits
"""

import asyncio
import logging
import json
from typing import Dict, Any
from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage,
    LoggingMiddleware,
    ConnectionLimiterMiddleware
)

# Configure logging to see middleware output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Create main router for chat functionality
chat_router = Router()

# Create separate router for statistics
stats_router = Router()

# Global connection limiter instance for statistics access
connection_limiter = None

@chat_router.connect()
async def handle_connect(websocket: WebSocket):
    """Handle user connection"""
    # Get connection limiter info from context
    limiter_info = websocket.context.get('connection_limiter', {})
    client_ip = limiter_info.get('ip', 'unknown')
    bypassed = limiter_info.get('bypassed', False)
    
    print(f"✅ New connection from IP: {client_ip}")
    if bypassed:
        reason = limiter_info.get('reason', 'unknown')
        print(f"   🛡️ Connection bypassed limits (reason: {reason})")
    else:
        stats = limiter_info.get('stats', {})
        print(f"   📊 Active connections from this IP: {stats.get('active_connections', 0)}")
        print(f"   📊 Recent attempts: {stats.get('recent_attempts', 0)}")
    
    # Send welcome message with connection info
    welcome_msg = {
        "type": "connection_status",
        "message": f"Welcome! Connected from IP: {client_ip}",
        "connection_info": limiter_info,
        "instructions": [
            "Send chat messages: {\"type\": \"chat\", \"text\": \"your message\"}",
            "Get stats: {\"type\": \"get_stats\"}",
            "Try opening multiple connections to test limits"
        ]
    }
    await websocket.send_json(welcome_msg)


@chat_router.message("chat") 
async def handle_chat_message(websocket: WebSocket, message: BaseMessage):
    """Chat message handler"""
    # Get message data
    if hasattr(message, 'text'):
        text = message.text
    else:
        text = str(message.dict().get('text', 'No text'))
    
    limiter_info = websocket.context.get('connection_limiter', {})
    client_ip = limiter_info.get('ip', 'unknown')
    
    print(f"💬 Chat message from {client_ip}: {text}")
    
    # Echo the message back
    response = {
        "type": "chat_response",
        "text": f"Echo from server: {text}",
        "your_ip": client_ip,
        "timestamp": str(asyncio.get_event_loop().time())
    }
    await websocket.send_json(response)


@chat_router.message("get_stats")
async def handle_get_stats(websocket: WebSocket, message: BaseMessage):
    """Handle request for connection statistics"""
    if connection_limiter:
        global_stats = connection_limiter.get_global_stats()
        
        limiter_info = websocket.context.get('connection_limiter', {})
        client_ip = limiter_info.get('ip', 'unknown')
        ip_stats = connection_limiter._get_stats_for_ip(client_ip)
        
        stats_response = {
            "type": "stats_response",
            "global_stats": global_stats,
            "your_ip_stats": ip_stats,
            "your_ip": client_ip
        }
        await websocket.send_json(stats_response)
    else:
        await websocket.send_json({
            "type": "error",
            "message": "Connection limiter not available"
        })


@chat_router.disconnect()
async def handle_disconnect(websocket: WebSocket, reason: str):
    """Handle user disconnection"""
    limiter_info = websocket.context.get('connection_limiter', {})
    client_ip = limiter_info.get('ip', 'unknown')
    print(f"❌ User from IP {client_ip} disconnected. Reason: {reason}")


# Statistics router for real-time monitoring
@stats_router.connect()
async def handle_stats_connect(websocket: WebSocket):
    """Handle connection to statistics endpoint"""
    print("📊 Statistics monitor connected")
    await websocket.send_json({
        "type": "stats_welcome",
        "message": "Connected to real-time statistics feed",
        "note": "You will receive stats updates every 5 seconds"
    })
    
    # Start statistics broadcasting
    asyncio.create_task(broadcast_stats(websocket))


async def broadcast_stats(websocket: WebSocket):
    """Broadcast statistics every 5 seconds"""
    try:
        while not websocket.closed:
            if connection_limiter:
                global_stats = connection_limiter.get_global_stats()
                
                stats_update = {
                    "type": "stats_update",
                    "timestamp": str(asyncio.get_event_loop().time()),
                    "global_stats": global_stats
                }
                await websocket.send_json(stats_update)
            
            await asyncio.sleep(5)  # Update every 5 seconds
    except Exception as e:
        print(f"Statistics broadcast ended: {e}")


@stats_router.disconnect()
async def handle_stats_disconnect(websocket: WebSocket, reason: str):
    """Handle statistics monitor disconnection"""
    print(f"📊 Statistics monitor disconnected. Reason: {reason}")


def create_connection_limiter() -> ConnectionLimiterMiddleware:
    """Create and configure connection limiter middleware"""
    # Define trusted IPs that bypass all limits
    trusted_ips = [
        "127.0.0.1",        # Localhost
        "::1",              # IPv6 localhost
        "192.168.1.100",    # Example trusted server
    ]
    
    limiter = ConnectionLimiterMiddleware(
        max_connections_per_ip=3,           # Max 3 concurrent connections per IP
        max_connections_per_minute=10,      # Max 10 new connections per minute
        sliding_window_size=60,             # 60 second sliding window
        whitelist_ips=trusted_ips,          # Trusted IPs
        cleanup_interval=120                # Cleanup every 2 minutes
    )
    
    print("🛡️ Connection Limiter configured:")
    print(f"   • Max concurrent connections per IP: {limiter.max_connections_per_ip}")
    print(f"   • Max new connections per minute: {limiter.max_connections_per_minute}")
    print(f"   • Sliding window size: {limiter.sliding_window_size}s")
    print(f"   • Trusted IPs: {', '.join(trusted_ips)}")
    
    return limiter


def main():
    """Main function - create and run server with connection limiter"""
    global connection_limiter
    
    print("🚀 Starting Connection Limiter Example Server")
    print("=" * 50)
    
    # Create server
    server = WebSocketServer()
    
    # Create and add connection limiter middleware
    connection_limiter = create_connection_limiter()
    
    # Add middleware to server (order matters!)
    server.add_middleware(LoggingMiddleware())      # Logging first
    server.add_middleware(connection_limiter)        # Connection limiting second
    
    # Add routers
    server.include_router(chat_router)               # Main chat functionality
    server.include_router(stats_router, prefix="/stats")  # Statistics at /stats
    
    print("\n📡 Server endpoints:")
    print("   • Main chat: ws://localhost:8000")
    print("   • Statistics: ws://localhost:8000/stats")
    
    print("\n🧪 Test scenarios:")
    print("   1. Normal usage: Connect 1-2 clients normally")
    print("   2. Connection limit test: Try 4+ connections from same IP")
    print("   3. Rate limit test: Open/close connections rapidly")
    print("   4. Statistics: Connect to /stats endpoint for live monitoring")
    
    print("\n⚠️  To test thoroughly, use tools like:")
    print("   • wscat: npm install -g wscat")
    print("   • Browser dev console with WebSocket")
    print("   • Python websocket-client library")
    
    print("\n🎯 Example commands:")
    print('   wscat -c ws://localhost:8000')
    print('   wscat -c ws://localhost:8000/stats')
    
    print("\n" + "=" * 50)
    print("🔥 Server starting... Press Ctrl+C to stop")
    
    try:
        # Run server
        server.run(host="localhost", port=8000)
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        
        # Show final statistics
        if connection_limiter:
            final_stats = connection_limiter.get_global_stats()
            print("\n📊 Final Statistics:")
            print(f"   • Total active connections: {final_stats['total_active_connections']}")
            print(f"   • Tracked IPs: {final_stats['tracked_ips']}")
            print(f"   • Recent connection attempts: {final_stats['total_recent_attempts']}")
    except Exception as e:
        print(f"\n❌ Server error: {e}")


if __name__ == "__main__":
    main() 