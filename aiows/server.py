"""
WebSocket server implementation
"""

import asyncio
import websockets
from .router import Router
from .dispatcher import MessageDispatcher
from .websocket import WebSocket


class WebSocketServer:
    """Main WebSocket server class for aiows framework"""
    
    def __init__(self):
        """Initialize WebSocket server"""
        self.host: str = "localhost"
        self.port: int = 8000
        self.router: Router = Router()
        self.dispatcher: MessageDispatcher = MessageDispatcher(self.router)
        self._connections: set = set()
    
    def include_router(self, router: Router) -> None:
        """Include router to the server
        
        Args:
            router: Router instance to include
        """
        self.router = router
        self.dispatcher = MessageDispatcher(self.router)
    
    async def _handle_connection(self, websocket, path: str) -> None:
        """Handle single WebSocket connection
        
        Args:
            websocket: Raw websocket connection
            path: Connection path
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
        async with websockets.serve(self._handle_connection, host, port):
            await asyncio.Future()  # run forever 