"""
WebSocket server implementation
"""

import asyncio
import websockets
from .router import Router
from .dispatcher import MessageDispatcher
from .websocket import WebSocket
from .middleware.base import BaseMiddleware
from typing import List


class WebSocketServer:
    """Main WebSocket server class for aiows framework"""
    
    def __init__(self):
        """Initialize WebSocket server"""
        self.host: str = "localhost"
        self.port: int = 8000
        self.router: Router = Router()
        self.dispatcher: MessageDispatcher = MessageDispatcher(self.router)
        self._connections: set = set()
        self._middleware: List[BaseMiddleware] = []
    
    def add_middleware(self, middleware: BaseMiddleware) -> None:
        """Add global middleware to the server
        
        Args:
            middleware: Middleware instance to add
        """
        self._middleware.append(middleware)
        # Update dispatcher with new middleware
        self._update_dispatcher_middleware()
    
    def _update_dispatcher_middleware(self) -> None:
        """Update dispatcher with combined middleware from server and router"""
        # Clear existing middleware
        self.dispatcher._middleware.clear()
        
        # Add server middleware first (they execute first)
        for middleware in self._middleware:
            self.dispatcher.add_middleware(middleware)
        
        # Add router middleware (they execute after server middleware)
        for middleware in self.router.get_all_middleware():
            self.dispatcher.add_middleware(middleware)
    
    def include_router(self, router: Router) -> None:
        """Include router to the server
        
        Args:
            router: Router instance to include
        """
        self.router = router
        self.dispatcher = MessageDispatcher(self.router)
        # Apply all middleware to new dispatcher
        self._update_dispatcher_middleware()
    
    async def _handle_connection(self, websocket) -> None:
        """Handle single WebSocket connection
        
        Args:
            websocket: Raw websocket connection (ServerConnection)
        """
        # Create WebSocket wrapper
        ws_wrapper = WebSocket(websocket)
        
        # Add to active connections
        self._connections.add(ws_wrapper)
        
        try:
            # Call dispatch_connect
            await self.dispatcher.dispatch_connect(ws_wrapper)
            
            # Message processing loop
            while not ws_wrapper.closed:
                try:
                    # Receive message and dispatch
                    message_data = await ws_wrapper.receive_json()
                    await self.dispatcher.dispatch_message(ws_wrapper, message_data)
                except Exception as e:
                    print(f"Error processing message: {str(e)}")
                    break
                    
        except Exception as e:
            print(f"Connection error: {str(e)}")
        finally:
            # Handle disconnection
            reason = "Connection closed"
            try:
                await self.dispatcher.dispatch_disconnect(ws_wrapper, reason)
            except Exception as e:
                print(f"Error in disconnect handler: {str(e)}")
            
            # Remove from connections
            self._connections.discard(ws_wrapper)
            
            # Ensure connection is closed
            if not ws_wrapper.closed:
                await ws_wrapper.close()
    
    def run(self, host: str = "localhost", port: int = 8000) -> None:
        """Start WebSocket server
        
        Args:
            host: Server host (default: localhost)
            port: Server port (default: 8000)
        """
        self.host = host
        self.port = port
        
        print(f"Starting WebSocket server on {host}:{port}")
        
        asyncio.run(self._run_server(host, port))
    
    async def _run_server(self, host: str, port: int) -> None:
        """Internal method to run the WebSocket server"""
        # Create wrapper function that properly handles the websockets.serve callback
        async def connection_handler(websocket):
            await self._handle_connection(websocket)
        
        async with websockets.serve(connection_handler, host, port):
            await asyncio.Future()  # run forever 