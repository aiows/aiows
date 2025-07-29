#!/usr/bin/env python3

import asyncio
from unittest.mock import Mock, AsyncMock
from aiows.router import Router
from aiows.dispatcher import MessageDispatcher, dispatcher_error_metrics
from aiows.exceptions import MessageValidationError
from aiows.middleware.base import BaseMiddleware

for attr in dir(dispatcher_error_metrics):
    if attr.endswith('_errors'):
        setattr(dispatcher_error_metrics, attr, 0)

async def test_middleware_chain():
    router = Router()
    dispatcher = MessageDispatcher(router)
    
    class ValidationMiddleware(BaseMiddleware):
        async def on_message(self, call_next, websocket, message_data):
            print("ValidationMiddleware: Before validation")
            if not message_data.get("user_id"):
                print("ValidationMiddleware: Raising MessageValidationError")
                raise MessageValidationError("Missing user_id")
            print("ValidationMiddleware: Calling next")
            await call_next(websocket, message_data)
            print("ValidationMiddleware: After next")
    
    dispatcher.add_middleware(ValidationMiddleware())
    
    @router.message()
    async def message_handler(websocket, message):
        print("Handler: Processing message")
        print(f"Handler: Message type = {message.type if hasattr(message, 'type') else 'no type'}")
        import traceback
        print("Handler: Stack trace:")
        traceback.print_stack()
        websocket.message_processed = True
    
    mock_websocket = Mock()
    mock_websocket.context = {}
    mock_websocket.remote_address = ('127.0.0.1', 8080)
    mock_websocket.closed = False
    mock_websocket.close = AsyncMock()
    
    print("Starting dispatch...")
    message_data = {"type": "chat", "text": "test"}
    await dispatcher.dispatch_message(mock_websocket, message_data)
    
    print(f"Client errors: {dispatcher_error_metrics.client_errors}")
    print(f"Handler called: {hasattr(mock_websocket, 'message_processed')}")
    
    for attr in dir(mock_websocket):
        if not attr.startswith('_'):
            try:
                value = getattr(mock_websocket, attr)
                print(f"mock_websocket.{attr} = {value}")
            except:
                pass

if __name__ == "__main__":
    asyncio.run(test_middleware_chain()) 