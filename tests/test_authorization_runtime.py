"""
Authorization Runtime Tests for aiows framework

Tests authorization (what users can do) beyond authentication (who they are):
- Role-based access control (admin, moderator, user, guest)
- Message-level authorization
- Room/channel access control
- Action permissions
- Resource access restrictions
"""

import pytest
import asyncio
import json
import threading
import socket
import time
from typing import Set, Dict

try:
    import websockets
except ImportError:
    pytest.skip("websockets library not available", allow_module_level=True)

from aiows import (
    WebSocketServer, 
    Router, 
    WebSocket, 
    BaseMessage,
    AuthMiddleware,
    BaseMiddleware
)
from aiows.middleware.auth import generate_auth_token


class RoleAuthorizationMiddleware(BaseMiddleware):
    
    def __init__(self, role_permissions: Dict[str, Set[str]]):
        self.role_permissions = role_permissions
    
    def _get_user_role(self, user_id: str) -> str:
        if user_id.startswith('admin'):
            return 'admin'
        elif user_id.startswith('mod'):
            return 'moderator'
        elif user_id.startswith('guest'):
            return 'guest'
        else:
            return 'user'
    
    def _check_permission(self, role: str, permission: str) -> bool:
        return permission in self.role_permissions.get(role, set())
    
    async def on_connect(self, handler, *args, **kwargs):
        websocket = args[0] if args else None
        if websocket and hasattr(websocket, 'context'):
            user_id = websocket.context.get('user_id')
            if user_id:
                role = self._get_user_role(user_id)
                websocket.context['role'] = role
                websocket.context['permissions'] = self.role_permissions.get(role, set())
        
        return await handler(*args, **kwargs)
    
    async def on_message(self, handler, *args, **kwargs):
        websocket = args[0] if args else None
        message_data = args[1] if len(args) > 1 else None
        
        if websocket and message_data:
            if isinstance(message_data, dict):
                message_type = message_data.get('type')
                role = websocket.context.get('role', 'guest')
                
                type_permission_map = {
                    'admin_action': 'admin_action',
                    'moderate': 'moderate',
                    'create_room': 'create_room',
                    'delete_room': 'delete_room',
                    'kick_user': 'kick_user'
                }
                
                required_permission = type_permission_map.get(message_type)
                
                if required_permission and not self._check_permission(role, required_permission):
                    await websocket.send_json({
                        "type": "error",
                        "code": "FORBIDDEN",
                        "message": f"Role '{role}' not authorized for action '{message_type}'"
                    })
                    return
        
        return await handler(*args, **kwargs)


class ResourceAuthorizationMiddleware(BaseMiddleware):
    
    def __init__(self):
        self.user_rooms = {
            'user': {'room1', 'room2'},
            'user1': {'room1', 'room2'},
            'user2': {'room2', 'room3'},
            'admin': {'room1', 'room2', 'room3', 'admin_room'},
            'admin1': {'room1', 'room2', 'room3', 'admin_room'},
            'mod1': {'room1', 'room2'},
            'guest': {'room1'},
            'guest1': {'room1'},
        }
    
    def _check_room_access(self, user_id: str, room_id: str) -> bool:
        return room_id in self.user_rooms.get(user_id, set())
    
    async def on_message(self, handler, *args, **kwargs):
        websocket = args[0] if args else None
        message_data = args[1] if len(args) > 1 else None
        
        if websocket and message_data:
            if isinstance(message_data, dict):
                room_id = message_data.get('room_id')
                user_id = websocket.context.get('user_id')
                
                if room_id and user_id:
                    if not self._check_room_access(user_id, room_id):
                        await websocket.send_json({
                            "type": "error", 
                            "code": "ROOM_ACCESS_DENIED",
                            "message": f"Access denied to room '{room_id}'"
                        })
                        return
                    else:
                        websocket.context['current_room_id'] = room_id
        
        return await handler(*args, **kwargs)


def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]


class AuthorizationTestServer:
    def __init__(self):
        self.server = None
        self.port = None
        self.server_thread = None
        
    def setup_authorization_router(self):
        router = Router()
        
        @router.connect()
        async def handle_connect(websocket: WebSocket):
            user_id = websocket.context.get('user_id', 'anonymous')
            role = websocket.context.get('role', 'guest')
            permissions = list(websocket.context.get('permissions', []))
            
            await websocket.send_json({
                "type": "connected",
                "user_id": user_id,
                "role": role,
                "permissions": permissions
            })
        
        @router.message("admin_action")
        async def handle_admin_action(websocket: WebSocket, message: BaseMessage):
            await websocket.send_json({
                "type": "admin_response",
                "status": "success",
                "message": "Admin action completed"
            })
        
        @router.message("room_message")
        async def handle_room_message(websocket: WebSocket, message: BaseMessage):
            room_id = getattr(message, 'room_id', None) or websocket.context.get('current_room_id')
            await websocket.send_json({
                "type": "room_response",
                "status": "success",
                "room_id": room_id,
                "message": "Message sent to room"
            })
        
        @router.message("moderate")
        async def handle_moderate(websocket: WebSocket, message: BaseMessage):
            await websocket.send_json({
                "type": "moderate_response",
                "status": "success"
            })
            
        return router
    
    def start_server_with_auth_middleware(self, middleware_list):
        self.port = get_free_port()
        
        def run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            self.server = WebSocketServer()
            
            for middleware in middleware_list:
                self.server.add_middleware(middleware)
            
            router = self.setup_authorization_router()
            self.server.include_router(router)
            
            try:
                self.server.run(host="localhost", port=self.port)
            except Exception as e:
                print(f"Server error: {e}")
        
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        time.sleep(0.5)
        
        return f"ws://localhost:{self.port}"
    
    def stop(self):
        if self.server_thread:
            self.server_thread.join(timeout=1)


@pytest.fixture
def auth_test_server():
    server = AuthorizationTestServer()
    yield server
    server.stop()


class TestRoleBasedAuthorization:
    @pytest.mark.asyncio
    async def test_admin_permissions(self, auth_test_server):
        role_permissions = {
            'admin': {'create_room', 'delete_room', 'kick_user', 'moderate', 'admin_action'},
            'moderator': {'kick_user', 'moderate'},
            'user': {'send_message', 'join_room'},
            'guest': {'send_message'}
        }
        
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        role_middleware = RoleAuthorizationMiddleware(role_permissions)
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, role_middleware])
        
        jwt_token = generate_auth_token(
            user_id="admin",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        admin_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(admin_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["role"] == "admin"
            assert "admin_action" in data["permissions"]
            assert "moderate" in data["permissions"]
            
            await websocket.send(json.dumps({
                "type": "admin_action"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "admin_response"
            assert data["status"] == "success"
    
    @pytest.mark.asyncio
    async def test_user_restricted_permissions(self, auth_test_server):
        role_permissions = {
            'admin': {'create_room', 'delete_room', 'kick_user', 'moderate', 'admin_action'},
            'user': {'send_message', 'join_room'},
        }
        
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        role_middleware = RoleAuthorizationMiddleware(role_permissions)
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, role_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        user_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(user_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["role"] == "user"
            assert "admin_action" not in data["permissions"]
            
            await websocket.send(json.dumps({
                "type": "admin_action"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "error"
            assert data["code"] == "FORBIDDEN"
            assert "not authorized" in data["message"]
    
    @pytest.mark.asyncio
    async def test_moderator_permissions(self, auth_test_server):
        role_permissions = {
            'admin': {'create_room', 'delete_room', 'kick_user', 'moderate', 'admin_action'},
            'moderator': {'kick_user', 'moderate'},
            'user': {'send_message', 'join_room'},
        }
        
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        role_middleware = RoleAuthorizationMiddleware(role_permissions)
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, role_middleware])
        
        jwt_token = generate_auth_token(
            user_id="mod",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        mod_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(mod_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["role"] == "moderator"
            assert "moderate" in data["permissions"]
            assert "admin_action" not in data["permissions"]
            
            await websocket.send(json.dumps({
                "type": "moderate"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "moderate_response"
            assert data["status"] == "success"


class TestResourceBasedAuthorization:
    @pytest.mark.asyncio
    async def test_room_access_granted(self, auth_test_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        resource_middleware = ResourceAuthorizationMiddleware()
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, resource_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        user_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(user_uri) as websocket:
            await websocket.recv()
            
            await websocket.send(json.dumps({
                "type": "room_message",
                "room_id": "room1",
                "text": "Hello room1"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "room_response"
            assert data["status"] == "success"
            assert data["room_id"] == "room1"
    
    @pytest.mark.asyncio
    async def test_room_access_denied(self, auth_test_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        resource_middleware = ResourceAuthorizationMiddleware()
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, resource_middleware])
        
        jwt_token = generate_auth_token(
            user_id="user",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        user_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(user_uri) as websocket:
            await websocket.recv()
            
            await websocket.send(json.dumps({
                "type": "room_message",
                "room_id": "room3",
                "text": "Hello room3"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "error"
            assert data["code"] == "ROOM_ACCESS_DENIED"
            assert "room3" in data["message"]
    
    @pytest.mark.asyncio
    async def test_admin_room_access(self, auth_test_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        resource_middleware = ResourceAuthorizationMiddleware()
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, resource_middleware])
        
        jwt_token = generate_auth_token(
            user_id="admin",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        admin_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(admin_uri) as websocket:
            await websocket.recv()
            
            await websocket.send(json.dumps({
                "type": "room_message",
                "room_id": "admin_room",
                "text": "Admin message"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "room_response"
            assert data["status"] == "success"
            assert data["room_id"] == "admin_room"
    
    @pytest.mark.asyncio
    async def test_guest_limited_access(self, auth_test_server):
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        resource_middleware = ResourceAuthorizationMiddleware()
        
        uri = auth_test_server.start_server_with_auth_middleware([auth_middleware, resource_middleware])
        
        jwt_token = generate_auth_token(
            user_id="guest",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        guest_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(guest_uri) as websocket:
            await websocket.recv()
            
            await websocket.send(json.dumps({
                "type": "room_message",
                "room_id": "room1",
                "text": "Guest message"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "room_response"
            assert data["status"] == "success"


class TestCombinedAuthorization:
    @pytest.mark.asyncio
    async def test_role_and_resource_combined(self, auth_test_server):
        role_permissions = {
            'admin': {'create_room', 'delete_room', 'moderate', 'admin_action'},
            'user': {'send_message', 'join_room'},
        }
        
        secret_key = "test_secret_key_32_characters_long_12345"
        auth_middleware = AuthMiddleware(secret_key, auth_timeout=3)
        role_middleware = RoleAuthorizationMiddleware(role_permissions)
        resource_middleware = ResourceAuthorizationMiddleware()
        
        uri = auth_test_server.start_server_with_auth_middleware([
            auth_middleware, role_middleware, resource_middleware
        ])
        
        jwt_token = generate_auth_token(
            user_id="user",
            secret_key=secret_key,
            ttl_seconds=300
        )
        
        user_uri = f"{uri}?token={jwt_token}"
        
        async with websockets.connect(user_uri) as websocket:
            response = await websocket.recv()
            data = json.loads(response)
            
            assert data["role"] == "user"
            assert "admin_action" not in data["permissions"]
            
            await websocket.send(json.dumps({
                "type": "room_message",
                "room_id": "room1",
                "text": "User message"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "room_response"
            assert data["status"] == "success"
            
            await websocket.send(json.dumps({
                "type": "admin_action",
                "room_id": "room1"
            }))
            
            response = await websocket.recv()
            data = json.loads(response)
            assert data["type"] == "error"
            assert data["code"] == "FORBIDDEN"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])