"""
Example demonstrating backpressure handling in aiows WebSocket framework.

This example shows:
- How to configure backpressure settings
- How to monitor connection health
- How slow clients are automatically handled
- How to access backpressure metrics
"""

import asyncio
import json
import time
from aiows import WebSocketServer, Router
from aiows.settings import create_settings


async def main():
    print("=== aiows Backpressure Handling Example ===\n")
    
    router = Router()
    
    @router.on_connect
    async def handle_connect(websocket):
        print(f"Client connected: {websocket.connection_id}")
        print(f"Backpressure enabled: {websocket.backpressure_enabled}")
        
        if websocket.backpressure_enabled:
            stats = websocket.get_backpressure_stats()
            print(f"Initial queue size: {stats['queue_size']}")
            print(f"Queue utilization: {stats['queue_utilization_percent']:.1f}%")
        
        await websocket.send_json({
            "type": "welcome",
            "message": "Connected to aiows server with backpressure protection!",
            "connection_id": websocket.connection_id
        })
    
    @router.on_message("chat")
    async def handle_chat(websocket, message):
        print(f"Received chat from {websocket.connection_id}: {message.get('text', '')}")
        
        broadcast_msg = {
            "type": "chat_broadcast",
            "sender": websocket.connection_id,
            "text": message.get('text', ''),
            "timestamp": time.time()
        }
        
        for i in range(5):
            await websocket.send_json({
                **broadcast_msg,
                "sequence": i
            })
    
    @router.on_message("simulate_slow_client")
    async def handle_slow_client_simulation(websocket, message):
        print(f"Simulating slow client for {websocket.connection_id}")
        
        for i in range(50):
            await websocket.send_json({
                "type": "bulk_message",
                "sequence": i,
                "data": f"Message {i} of bulk send"
            })
            
            if i % 10 == 0:
                stats = websocket.get_backpressure_stats()
                print(f"Queue size: {stats['queue_size']}, "
                      f"Utilization: {stats['queue_utilization_percent']:.1f}%, "
                      f"Is slow client: {stats['is_slow_client']}")
    
    @router.on_message("get_stats")
    async def handle_get_stats(websocket, message):
        if websocket.backpressure_enabled:
            stats = websocket.get_backpressure_stats()
            await websocket.send_json({
                "type": "stats_response",
                "stats": stats
            })
        else:
            await websocket.send_json({
                "type": "stats_response",
                "error": "Backpressure not enabled"
            })
    
    @router.on_disconnect
    async def handle_disconnect(websocket, reason):
        print(f"Client disconnected: {websocket.connection_id}, reason: {reason}")
        
        if websocket.backpressure_enabled:
            final_stats = websocket.get_backpressure_stats()
            print(f"Final stats - Queue size: {final_stats['queue_size']}, "
                  f"Was slow client: {final_stats['is_slow_client']}")
    
    settings = create_settings("development")
    
    settings.backpressure.enabled = True
    settings.backpressure.send_queue_max_size = 20
    settings.backpressure.send_queue_overflow_strategy = "drop_oldest"
    settings.backpressure.slow_client_threshold = 75
    settings.backpressure.slow_client_timeout = 10.0
    settings.backpressure.max_response_time_ms = 2000
    settings.backpressure.enable_send_metrics = True
    
    print("Backpressure Configuration:")
    print(f"- Queue max size: {settings.backpressure.send_queue_max_size}")
    print(f"- Overflow strategy: {settings.backpressure.send_queue_overflow_strategy}")
    print(f"- Slow client threshold: {settings.backpressure.slow_client_threshold}%")
    print(f"- Slow client timeout: {settings.backpressure.slow_client_timeout}s")
    print(f"- Max response time: {settings.backpressure.max_response_time_ms}ms")
    print()
    
    server = WebSocketServer.from_settings(settings)
    server.include_router(router)
    
    print("Starting server on ws://localhost:8000")
    print("\nTo test backpressure:")
    print("1. Connect with a WebSocket client")
    print("2. Send: {\"type\": \"chat\", \"text\": \"Hello!\"}")
    print("3. Send: {\"type\": \"simulate_slow_client\"}")
    print("4. Send: {\"type\": \"get_stats\"}")
    print("\nPress Ctrl+C to stop")
    print()
    
    async def monitor_server_stats():
        while True:
            await asyncio.sleep(5)
            try:
                backpressure_stats = server.get_backpressure_stats()
                global_stats = backpressure_stats['global_stats']
                
                if global_stats['active_connections'] > 0:
                    print(f"\n=== Server Stats ===")
                    print(f"Active connections: {global_stats['active_connections']}")
                    print(f"Messages queued: {global_stats['messages_queued']}")
                    print(f"Messages sent: {global_stats['messages_sent']}")
                    print(f"Messages dropped: {global_stats['messages_dropped']}")
                    print(f"Slow client disconnections: {global_stats['slow_client_disconnections']}")
                    print(f"Average send time: {global_stats['average_send_time_ms']:.2f}ms")
                    print(f"Throughput: {global_stats['throughput_messages_per_second']:.2f} msg/s")
                    
                    slow_connections = server.get_slow_connections()
                    if slow_connections:
                        print(f"Slow connections: {len(slow_connections)}")
                        for conn in slow_connections:
                            print(f"  - {conn['connection_id']}: queue {conn['queue_size']}/{conn.get('max_queue_size', 'unknown')}")
                    print()
            except Exception as e:
                print(f"Error monitoring stats: {e}")
    
    monitor_task = asyncio.create_task(monitor_server_stats())
    
    try:
        await server.serve("localhost", 8000)
    except KeyboardInterrupt:
        print("\nShutting down server...")
        monitor_task.cancel()
        await server.shutdown()
        
        final_stats = server.get_backpressure_stats()
        print("\n=== Final Statistics ===")
        print(json.dumps(final_stats['global_stats'], indent=2))


if __name__ == "__main__":
    asyncio.run(main()) 