# aiows

Modern WebSocket framework for Python inspired by aiogram. Build real-time applications with declarative routing, middleware support, and built-in authentication.

## Key Features

- **Declarative routing** with decorators (@router.connect, @router.message)
- **Middleware system** for authentication, logging, rate limiting, connection flooding protection
- **Typed messages** with Pydantic validation
- **Context management** for connection-specific data
- **Built-in authentication** with token support
- **DDoS protection** with IP-based connection limiting and rate limiting
- **Graceful shutdown** with signal handlers and connection cleanup
- **Exception handling** with graceful error recovery
- **Production ready** with comprehensive test coverage

## Installation

```bash
pip install aiows
```

**Requirements:** Python 3.8+, pydantic>=2.0.0, websockets>=10.0

## Quick Start

```python
from aiows import WebSocketServer, Router, WebSocket, BaseMessage

router = Router()

@router.connect()
async def on_connect(websocket: WebSocket):
    await websocket.send_json({"type": "welcome", "message": "Connected!"})

@router.message("chat")
async def on_chat(websocket: WebSocket, message: BaseMessage):
    # Echo message back
    await websocket.send_json({
        "type": "chat_response", 
        "echo": message.dict()
    })

@router.disconnect()
async def on_disconnect(websocket: WebSocket, reason: str):
    print(f"Client disconnected: {reason}")

# Create and run server
server = WebSocketServer()
server.include_router(router)

# Optional: Configure graceful shutdown timeout
server.set_shutdown_timeout(15.0)

# Start server (supports graceful shutdown with Ctrl+C)
server.run(host="localhost", port=8000)
```

Connect via WebSocket: `ws://localhost:8000`

## Middleware System

aiows provides a powerful middleware system for cross-cutting concerns like authentication, logging, and rate limiting.

### Authentication

```python
from aiows import WebSocketServer, Router, AuthMiddleware

# Token-based authentication
auth = AuthMiddleware("your-secret-key")

server = WebSocketServer()
server.add_middleware(auth)

@router.connect()
async def authenticated_handler(websocket: WebSocket):
    user_id = websocket.context.get('user_id')  # Set by AuthMiddleware
    await websocket.send_json({"user_id": user_id, "authenticated": True})
```

**Connect with token:**
- Query param: `ws://localhost:8000?token=user123your-secret-key`
- Header: `Authorization: Bearer user456your-secret-key`

### Logging

```python
from aiows import LoggingMiddleware

# Structured logging for all WebSocket events
logging_middleware = LoggingMiddleware("myapp.websocket")
server.add_middleware(logging_middleware)

# Logs connection, message processing time, disconnection reason
```

### Rate Limiting

```python
from aiows import RateLimitingMiddleware

# Limit to 60 messages per minute per connection
rate_limit = RateLimitingMiddleware(max_messages_per_minute=60)
server.add_middleware(rate_limit)

# Automatically closes connections exceeding limit with code 4429
```

### Connection Flooding Protection

```python
from aiows import ConnectionLimiterMiddleware

# Protect against connection flooding attacks
connection_limiter = ConnectionLimiterMiddleware(
    max_connections_per_ip=10,          # Max concurrent connections per IP
    max_connections_per_minute=30,      # Max new connections per minute
    sliding_window_size=60,             # Sliding window in seconds
    whitelist_ips=["192.168.1.100"],    # Trusted IPs bypass limits
    cleanup_interval=300                # Memory cleanup interval
)
server.add_middleware(connection_limiter)

# Monitors connection patterns and blocks suspicious IPs with code 4008
```

### Middleware Order

```python
server = WebSocketServer()

# Middleware executes in order
server.add_middleware(LoggingMiddleware())                    # Log all activity
server.add_middleware(ConnectionLimiterMiddleware())          # Block flooding attacks
server.add_middleware(AuthMiddleware("secret"))               # Authenticate users
server.add_middleware(RateLimitingMiddleware(60))            # Rate limit messages

# Router middleware executes after server middleware
router.add_middleware(CustomMiddleware())
server.include_router(router)
```

## Configuration System

aiows provides a centralized configuration system with environment variable support, validation, and different profiles for development, production, and testing environments.

### Basic Configuration

```python
from aiows.settings import AiowsSettings, create_settings

# Create settings with default development profile
settings = AiowsSettings()

# Or specify profile explicitly
settings = AiowsSettings(profile="production")

# Or use environment variable AIOWS_PROFILE
settings = create_settings()  # Reads AIOWS_PROFILE env var

# Access configuration values
print(f"Server will run on {settings.server.host}:{settings.server.port}")
print(f"Production mode: {settings.server.is_production}")
print(f"Rate limit: {settings.rate_limit.max_messages_per_minute} msg/min")
```

### Environment Variables

All configuration values can be overridden using environment variables:

```bash
# Server configuration
export AIOWS_HOST=0.0.0.0
export AIOWS_PORT=9000
export AIOWS_IS_PRODUCTION=true

# SSL configuration
export AIOWS_SSL_CERT_FILE=/path/to/cert.pem
export AIOWS_SSL_KEY_FILE=/path/to/key.pem

# Authentication
export AIOWS_SECRET_KEY=your-256-bit-secret-key-here
export AIOWS_TOKEN_TTL=1800

# Rate limiting
export AIOWS_MAX_MESSAGES_PER_MINUTE=30
export AIOWS_MAX_CONNECTIONS_PER_IP=5

# Logging
export AIOWS_LOG_LEVEL=WARNING
export AIOWS_USE_JSON_FORMAT=true
```

### Configuration Profiles

#### Development Profile (default)
- Host: `localhost`, Port: `8000`
- SSL: Optional
- Logging: DEBUG level, detailed output
- Rate limiting: Permissive (120 msg/min, 20 conn/IP)
- Security: Relaxed for development

#### Production Profile
- Host: `0.0.0.0`, SSL: Required
- Logging: WARNING level, JSON format, data sanitization
- Rate limiting: Strict (30 msg/min, 5 conn/IP)
- Security: Enhanced validation and protection

#### Testing Profile
- Host: `127.0.0.1`, Port: `8001`
- Logging: ERROR level only
- Rate limiting: Very permissive (1000 msg/min)
- Fast timeouts for quick test execution

### Using Configuration with Server

```python
from aiows import WebSocketServer, Router
from aiows.settings import AiowsSettings
from aiows.middleware import (
    AuthMiddleware, 
    RateLimitingMiddleware, 
    ConnectionLimiterMiddleware,
    LoggingMiddleware
)

# Load configuration
settings = AiowsSettings(profile="production")

# Create server with SSL if configured
server = WebSocketServer(
    is_production=settings.server.is_production,
    require_ssl_in_production=settings.server.require_ssl_in_production
)

# Configure middleware using settings
if settings.logging.enabled:
    server.add_middleware(LoggingMiddleware(
        logger_name=settings.logging.logger_name,
        log_level=settings.logging.log_level,
        use_json_format=settings.logging.use_json_format,
        sanitize_data=settings.logging.sanitize_data
    ))

if settings.connection_limiter.enabled:
    server.add_middleware(ConnectionLimiterMiddleware(
        max_connections_per_ip=settings.connection_limiter.max_connections_per_ip,
        max_connections_per_minute=settings.connection_limiter.max_connections_per_minute,
        whitelist_ips=settings.connection_limiter.whitelist_ips
    ))

if settings.rate_limit.enabled:
    server.add_middleware(RateLimitingMiddleware(
        max_messages_per_minute=settings.rate_limit.max_messages_per_minute
    ))

if settings.auth.enabled:
    server.add_middleware(AuthMiddleware(
        secret_key=settings.auth.secret_key,
        token_ttl=settings.auth.token_ttl,
        enable_ip_validation=settings.auth.enable_ip_validation
    ))

# Configure server timeouts
server.set_shutdown_timeout(settings.server.shutdown_timeout)

# Start server
server.run(
    host=settings.server.host,
    port=settings.server.port
)
```

### Configuration Validation

The configuration system includes built-in validation:

```python
from aiows.settings import AiowsSettings
from aiows.config import ConfigValidationError

try:
    settings = AiowsSettings()
    
    # All validation happens automatically
    settings.server.port = 8080  # Valid
    settings.server.port = 0     # Raises ConfigValidationError
    
except ConfigValidationError as e:
    print(f"Configuration error: {e}")
```

### Configuration Reloading

Reload configuration from environment variables without restarting:

```python
settings = AiowsSettings()

# Change environment variables
os.environ['AIOWS_HOST'] = 'new.host.com'
os.environ['AIOWS_PORT'] = '9000'

# Reload configuration
settings.reload()

print(f"New host: {settings.server.host}")  # new.host.com
print(f"New port: {settings.server.port}")  # 9000
```

### Export Environment Template

Generate environment variable templates for deployment:

```python
from aiows.settings import AiowsSettings

settings = AiowsSettings(profile="production")

# Export complete environment template
template = settings.export_env_template("production.env")

# Example output:
# AIOWS_PROFILE=production
# AIOWS_HOST=0.0.0.0
# AIOWS_PORT=8000
# AIOWS_IS_PRODUCTION=true
# AIOWS_SECRET_KEY=***CHANGE_ME***
# ... (all configuration options with descriptions)
```

### Configuration Sections

The configuration system includes these sections:

- **ServerConfig**: Host, port, SSL, timeouts
- **AuthConfig**: Authentication settings, tokens, security
- **RateLimitConfig**: Message rate limiting
- **ConnectionLimiterConfig**: Connection flood protection  
- **LoggingConfig**: Logging levels, format, data sanitization
- **SecurityConfig**: Message size limits, security headers

### Advanced Configuration

```python
from aiows.config import BaseConfig, ConfigValue, positive_int

# Create custom configuration section
class MyAppConfig(BaseConfig):
    database_url = ConfigValue(
        default="sqlite:///app.db",
        description="Database connection URL",
        sensitive=True
    )
    
    max_workers = ConfigValue(
        default=4,
        validator=positive_int,
        type_cast=int,
        description="Maximum worker processes"
    )

# Use in your application
config = MyAppConfig()
print(f"DB URL: {config.database_url}")
print(f"Workers: {config.max_workers}")
```

## Message Types

Define typed message schemas with Pydantic:

```python
from aiows import BaseMessage, ChatMessage, JoinRoomMessage

@router.message("chat")
async def handle_chat(websocket: WebSocket, message: ChatMessage):
    # message.user_id, message.text are validated and typed
    pass

@router.message("join_room") 
async def handle_join(websocket: WebSocket, message: JoinRoomMessage):
    # message.room_id, message.user_name are validated
    pass
```

## Context Management

Store connection-specific data in `websocket.context`:

```python
@router.connect()
async def on_connect(websocket: WebSocket):
    websocket.context['session_id'] = generate_session_id()
    websocket.context['permissions'] = get_user_permissions()

@router.message("action")
async def on_action(websocket: WebSocket, message: BaseMessage):
    if 'admin' not in websocket.context.get('permissions', []):
        await websocket.send_json({"error": "Permission denied"})
        return
```

## Connection Monitoring

aiows provides real-time monitoring capabilities for tracking active connections and preventing memory leaks:

```python
from aiows import WebSocketServer, Router

server = WebSocketServer()
router = Router()

@router.connect()
async def on_connect(websocket: WebSocket):
    # Get current connection stats
    active_count = server.get_active_connections_count()
    total_count = server.get_total_connections_count()
    
    await websocket.send_json({
        "type": "connected",
        "active_connections": active_count,
        "total_connections": total_count
    })

@router.message("stats")
async def get_stats(websocket: WebSocket, message: BaseMessage):
    # Get comprehensive connection statistics
    stats = server.get_connection_stats()
    await websocket.send_json({
        "type": "server_stats",
        "stats": stats
    })
    # Example response:
    # {
    #   "active_connections": 15,
    #   "total_connections": 1247,
    #   "connection_count_tracked": 15
    # }

server.include_router(router)
server.run("localhost", 8000)
```

### Memory Management Features

- **WeakSet Storage** - Automatic cleanup of dead connection references
- **Periodic Cleanup** - Orphaned connections cleaned every 30 seconds  
- **Memory Leak Prevention** - Proper cleanup even on sudden disconnects
- **Real-time Monitoring** - Track active/total connection counts

### Monitoring Methods

- `get_active_connections_count()` - Current number of active connections
- `get_total_connections_count()` - Total connections since server start
- `get_connection_stats()` - Comprehensive connection statistics

## Error Handling

```python
from aiows.exceptions import MessageValidationError, ConnectionError

@router.message("data")
async def handle_data(websocket: WebSocket, message: BaseMessage):
    try:
        # Process message
        result = process_message(message)
        await websocket.send_json({"result": result})
    except MessageValidationError as e:
        await websocket.send_json({"error": f"Invalid message: {e}"})
    except Exception as e:
        await websocket.send_json({"error": "Internal server error"})
```

## Graceful Shutdown

aiows provides robust graceful shutdown mechanisms for production deployments with proper connection cleanup and signal handling.

### Signal Handlers

Automatic graceful shutdown on SIGTERM and SIGINT (Ctrl+C):

```python
from aiows import WebSocketServer, Router

server = WebSocketServer()
router = Router()

# Configure graceful shutdown timeout (default: 30 seconds)
server.set_shutdown_timeout(15.0)

@router.connect()
async def on_connect(websocket: WebSocket):
    await websocket.send_json({"type": "connected"})

server.include_router(router)

# Signal handlers automatically registered
server.run("localhost", 8000)
# Press Ctrl+C for graceful shutdown
```

### Programmatic Shutdown

Trigger graceful shutdown from code:

```python
@router.message("admin_shutdown")
async def handle_admin_shutdown(websocket: WebSocket, message: BaseMessage):
    # Notify client of shutdown
    await websocket.send_json({
        "type": "shutdown_initiated", 
        "message": "Server shutting down gracefully..."
    })
    
    # Trigger graceful shutdown with custom timeout
    await server.shutdown(timeout=10.0)
```

### Shutdown Process

1. **Signal Detection** - SIGTERM/SIGINT triggers shutdown
2. **Connection Notification** - All connections receive disconnect events
3. **Graceful Close** - WebSocket close frames sent with code 1001
4. **Timeout Protection** - Force close after timeout if needed
5. **Resource Cleanup** - Memory and temporary files cleaned up

### Advanced Configuration

```python
server = WebSocketServer()

# Configure shutdown behavior
server.set_shutdown_timeout(30.0)  # 30 seconds for graceful close

# Check shutdown state
if server.is_shutting_down:
    print("Server is in shutdown process")

# Custom shutdown logic
@router.disconnect()
async def on_disconnect(websocket: WebSocket, reason: str):
    if reason == "Server shutdown":
        # Handle shutdown-specific cleanup
        await cleanup_user_session(websocket)
    else:
        # Handle normal disconnection
        await log_disconnection(websocket, reason)
```

### Docker Integration

For Docker containers, graceful shutdown works seamlessly:

```dockerfile
FROM python:3.11-slim

COPY . /app
WORKDIR /app

RUN pip install aiows

# Graceful shutdown on container stop
CMD ["python", "server.py"]
```

The server will receive SIGTERM from `docker stop` and shutdown gracefully within the configured timeout.

## Custom Middleware

```python
from aiows import BaseMiddleware

class CustomMiddleware(BaseMiddleware):
    async def on_connect(self, handler, websocket):
        # Pre-processing
        print(f"Connection from {websocket.remote_address}")
        
        # Call next middleware/handler
        result = await handler(websocket)
        
        # Post-processing
        print("Connection handled")
        return result
    
    async def on_message(self, handler, websocket, message):
        # Add custom logic here
        return await handler(websocket, message)
```

## Testing

Run the test suite:

```bash
# Basic tests
pytest tests/test_basic.py

# Integration tests  
pytest tests/test_integration.py

# Middleware runtime tests
pytest tests/test_middleware_runtime.py

# All tests
pytest tests/
```

## Examples

Check out `/examples` directory:
- `simple_chat.py` - Basic chat server
- `middleware_example.py` - Authentication and middleware usage  
- `graceful_shutdown_example.py` - Graceful shutdown demonstration
- `connection_limiter_example.py` - DDoS protection example
- `validation_example.py` - Message validation example

## API Reference

### WebSocketServer
- `add_middleware(middleware)` - Add global middleware
- `include_router(router)` - Add router with handlers
- `run(host, port)` - Start the server (blocking)
- `serve(host, port)` - Start the server (async)
- `shutdown(timeout=None)` - Trigger graceful shutdown
- `set_shutdown_timeout(timeout)` - Configure shutdown timeout
- `is_shutting_down` - Check if server is shutting down
- `get_active_connections_count()` - Get current active connections count
- `get_total_connections_count()` - Get total connections since server start
- `get_connection_stats()` - Get comprehensive connection statistics

### Router  
- `@router.connect()` - Connection handler decorator
- `@router.message(message_type)` - Message handler decorator  
- `@router.disconnect()` - Disconnection handler decorator
- `add_middleware(middleware)` - Add router-specific middleware

### WebSocket
- `send_json(data)` - Send JSON message
- `receive_json()` - Receive JSON message
- `context` - Dict for connection-specific data
- `close(code, reason)` - Close connection

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature-name`)
3. Make changes with tests
4. Run test suite (`pytest tests/`)
5. Submit pull request

## License

MIT License. See LICENSE file for details.

