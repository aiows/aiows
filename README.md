# aiows

Modern WebSocket framework inspired by aiogram. Built for developers who ship fast.

## Install

```bash
pip install aiows
```

## Quick Start

```python
from aiows import WebSocketServer, Router, ChatMessage, WebSocket

router = Router()

@router.connect()
async def on_connect(websocket: WebSocket):
    await websocket.send_json({"type": "welcome"})

@router.message("chat")
async def handle_chat(websocket: WebSocket, message: ChatMessage):
    await websocket.send_json({
        "type": "response", 
        "text": f"Echo: {message.text}"
    })

server = WebSocketServer()
server.include_router(router)
server.run("localhost", 8000)
```

That's it. Your WebSocket server is running.

## Real Features

### Authentication
```python
from aiows import AuthMiddleware

auth = AuthMiddleware("your-secret-key")
server.add_middleware(auth)

# Connect with: ws://localhost:8000?token=user123your-secret-key
```

### Rate Limiting
```python
from aiows import RateLimitingMiddleware

rate_limit = RateLimitingMiddleware(max_messages_per_minute=60)
server.add_middleware(rate_limit)
```

### SSL/TLS Support
```python
server = WebSocketServer()
server.run("localhost", 8443, ssl=True)  # Auto-generates dev certs
```

### Production Config
```python
from aiows import create_production_server

server = create_production_server()
server.include_router(router)
server.run()
```

## Message Types

```python
from aiows import BaseMessage, ChatMessage, JoinRoomMessage

@router.message("join")
async def handle_join(websocket: WebSocket, message: JoinRoomMessage):
    room_id = message.room_id
    user_name = message.user_name
    # Handle room join logic
```

## Health Checks

```python
from aiows import setup_health_checks

health_checker = setup_health_checks(server, http_port=9000)
# GET /health returns server status
```

## Connection Stats

```python
@router.message("stats")
async def get_stats(websocket: WebSocket, message):
    stats = server.get_connection_stats()
    await websocket.send_json(stats)
```

## Graceful Shutdown

Built-in. Press Ctrl+C and all connections close properly.

```python
# Or programmatically
await server.shutdown(timeout=30)
```

## Configuration

Environment variables or config objects:

```python
from aiows import AiowsSettings

settings = AiowsSettings(profile="production")
server = WebSocketServer.from_settings(settings)
```

## Middleware Stack

Order matters:

```python
server.add_middleware(LoggingMiddleware())
server.add_middleware(ConnectionLimiterMiddleware())  
server.add_middleware(AuthMiddleware("secret"))
server.add_middleware(RateLimitingMiddleware(60))
```

## Error Handling

```python
from aiows.exceptions import MessageValidationError

@router.message("data")
async def handle_data(websocket: WebSocket, message):
    try:
        result = process_data(message)
        await websocket.send_json({"result": result})
    except MessageValidationError:
        await websocket.send_json({"error": "Invalid data"})
```

## Examples

Check `/examples` for:
- Secure chat with SSL
- Authentication flow
- Middleware configuration
- Production deployment

## Why aiows?

- **Fast setup**: 5 lines to working server
- **Security features**: SSL, auth, rate limiting, health checks
- **Type safe**: Full type hints, Pydantic validation
- **Async native**: Built on asyncio, handles thousands of connections
- **Middleware system**: Compose functionality like Express.js
- **Zero config**: Works out of box, configurable when needed

## Roadmap

- [ ] Simplify middleware execution system
- [ ] Fix connection management race conditions  
- [ ] Add rooms/channels functionality
- [ ] Optimize WebSocket performance locks
- [ ] Add connection pooling support
- [ ] Improve error handling consistency
- [ ] Add broadcasting capabilities
- [ ] Performance benchmarking suite
- [ ] Enhanced documentation

## License

MIT