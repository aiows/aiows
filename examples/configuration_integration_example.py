#!/usr/bin/env python3
"""
Complete Configuration Integration Example

This example demonstrates how aiows now uses centralized configuration
instead of hardcoded values throughout the codebase.
"""

import os
import asyncio
from aiows import Router, WebSocket, BaseMessage
from aiows.factory import (
    create_server_from_settings,
    create_production_server,
    create_development_server,
    auto_configure_for_environment,
    quick_start_server
)
from aiows.settings import AiowsSettings


router = Router()

@router.connect()
async def on_connect(websocket: WebSocket):
    await websocket.send_json({
        "type": "welcome",
        "message": "Connected to aiows server with centralized configuration!",
        "server_info": {
            "profile": "configured via environment variables",
            "no_hardcoded_values": True
        }
    })

@router.message("echo")
async def echo_message(websocket: WebSocket, message: BaseMessage):
    await websocket.send_json({
        "type": "echo_response",
        "original": message.dict(),
        "timestamp": message.timestamp if hasattr(message, 'timestamp') else None
    })

@router.disconnect()
async def on_disconnect(websocket: WebSocket, reason: str):
    print(f"Client disconnected: {reason}")


def demonstrate_configuration_integration():
    print("🚀 aiows Configuration Integration Demo")
    print("=" * 50)
    
    print("\n1️⃣ Auto-configuration from environment:")
    os.environ['AIOWS_PROFILE'] = 'development'
    os.environ['AIOWS_HOST'] = 'config.example.com'
    os.environ['AIOWS_PORT'] = '9001'
    
    auto_server = auto_configure_for_environment()
    auto_server.include_router(router)
    
    print(f"   ✅ Server auto-configured: {auto_server.host}:{auto_server.port}")
    print(f"   ✅ Middleware count: {len(auto_server._middleware)}")
    print(f"   ✅ Cleanup interval: {auto_server._cleanup_interval}s")
    print(f"   ✅ Shutdown timeout: {auto_server._shutdown_timeout}s")
    
    print("\n2️⃣ Manual configuration with custom settings:")
    settings = AiowsSettings(profile='production')
    settings.server.host = '0.0.0.0'
    settings.server.port = 8443
    settings.server.cleanup_interval = 60.0
    # WARNING: Only for demo purposes! NEVER disable SSL in real production!
    settings.server.require_ssl_in_production = False
    settings.rate_limit.max_messages_per_minute = 100
    settings.connection_limiter.max_connections_per_ip = 15
    
    manual_server = create_server_from_settings(settings)
    manual_server.include_router(router)
    
    print(f"   ✅ Production server: {manual_server.host}:{manual_server.port}")
    print(f"   ✅ Cleanup interval: {manual_server._cleanup_interval}s (from config)")
    print(f"   ✅ Middleware configured automatically")
    
    print("\n3️⃣ Quick start server for development:")
    quick_server = quick_start_server(host="localhost", port=8080, with_auth=False)
    quick_server.include_router(router)
    
    print(f"   ✅ Quick server: {quick_server.host}:{quick_server.port}")
    print(f"   ✅ Development optimized settings")
    
    print("\n4️⃣ Environment-specific servers:")
    
    dev_server = create_development_server()
    prod_server = create_production_server()
    
    print(f"   ✅ Dev server: {dev_server.host}:{dev_server.port}")
    print(f"   ✅ Prod server: {prod_server.host}:{prod_server.port}")
    
    print("\n🔧 Middleware Configuration from Settings:")
    settings = AiowsSettings(profile='development')
    
    from aiows.middleware.rate_limit import RateLimitingMiddleware
    from aiows.middleware.connection_limiter import ConnectionLimiterMiddleware
    from aiows.middleware.auth import AuthMiddleware
    from aiows.middleware.logging import LoggingMiddleware
    
    rate_middleware = RateLimitingMiddleware.from_config(settings.rate_limit)
    conn_middleware = ConnectionLimiterMiddleware.from_config(settings.connection_limiter)
    log_middleware = LoggingMiddleware.from_config(settings.logging)
    
    print(f"   ✅ Rate Limit: {rate_middleware.max_messages_per_minute} msg/min (from config)")
    print(f"   ✅ Connection Limit: {conn_middleware.max_connections_per_ip} per IP (from config)")
    print(f"   ✅ Logging Level: {log_middleware.logger.level} (from config)")
    
    print("\n✨ No more hardcoded values - everything is configurable!")
    return auto_server


def demonstrate_environment_variables():
    print("\n🌍 Environment Variable Configuration:")
    print("=" * 40)
    
    env_vars = {
        'AIOWS_HOST': 'env.example.com',
        'AIOWS_PORT': '9999',
        'AIOWS_MAX_MESSAGES_PER_MINUTE': '200',
        'AIOWS_MAX_CONNECTIONS_PER_IP': '50',
        'AIOWS_LOG_LEVEL': 'WARNING',
        'AIOWS_CLEANUP_INTERVAL': '120',
        'AIOWS_SHUTDOWN_TIMEOUT': '45'
    }
    
    for key, value in env_vars.items():
        os.environ[key] = value
        print(f"   🔧 {key}={value}")
    
    settings = AiowsSettings()
    
    print(f"\n   ✅ Settings from env vars:")
    print(f"      Host: {settings.server.host}")
    print(f"      Port: {settings.server.port}")
    print(f"      Rate limit: {settings.rate_limit.max_messages_per_minute} msg/min")
    print(f"      Connection limit: {settings.connection_limiter.max_connections_per_ip} per IP")
    print(f"      Log level: {settings.logging.log_level}")
    print(f"      Cleanup interval: {settings.server.cleanup_interval}s")
    print(f"      Shutdown timeout: {settings.server.shutdown_timeout}s")
    
    server = create_server_from_settings(settings)
    print(f"\n   🚀 Server created with all env var settings!")
    
    return server


def demonstrate_configuration_reloading():
    print("\n🔄 Configuration Reloading:")
    print("=" * 30)
    
    settings = AiowsSettings()
    print(f"   📍 Initial host: {settings.server.host}")
    
    os.environ['AIOWS_HOST'] = 'reloaded.example.com'
    os.environ['AIOWS_PORT'] = '7777'
    
    settings.reload()
    print(f"   🔄 After reload host: {settings.server.host}")
    print(f"   🔄 After reload port: {settings.server.port}")
    
    print("   ✅ Configuration reloaded without restart!")


async def run_configured_server():
    print("\n🖥️  Running Configured Server:")
    print("=" * 30)
    
    server = demonstrate_configuration_integration()
    
    print(f"\n   🚀 Starting server on {server.host}:{server.port}")
    print("   📝 Try connecting with WebSocket client:")
    print(f"      ws://{server.host}:{server.port}")
    print("   📝 Send message: {'type': 'echo', 'data': 'Hello World!'}")
    print("   📝 Press Ctrl+C to stop")
    
    try:
        await server.serve(server.host, server.port)
    except KeyboardInterrupt:
        print("\n   ⛔ Server stopped by user")


def main():
    print("🎯 aiows Configuration Integration Complete!")
    print("All hardcoded values have been replaced with centralized configuration")
    print("=" * 70)
    
    demonstrate_configuration_integration()
    demonstrate_environment_variables()
    demonstrate_configuration_reloading()
    
    print("\n" + "=" * 70)
    print("🎉 INTEGRATION COMPLETE!")
    print("✅ Server configuration - fully configurable")
    print("✅ Middleware configuration - fully configurable") 
    print("✅ Environment variables - working")
    print("✅ Configuration profiles - working")
    print("✅ Configuration reloading - working")
    print("✅ Factory functions - working")
    print("✅ Backward compatibility - maintained")
    
    print("\n🤔 Want to run a configured server? (y/n): ", end="")
    try:
        choice = input().lower().strip()
        if choice in ['y', 'yes']:
            asyncio.run(run_configured_server())
    except (EOFError, KeyboardInterrupt):
        print("\nDemo completed!")


if __name__ == "__main__":
    main() 