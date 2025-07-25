"""
Type definitions for aiows
"""

from datetime import datetime
from typing import Literal, Tuple
from pydantic import BaseModel, Field


class BaseMessage(BaseModel):
    """Base class for all WebSocket messages"""
    type: str
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def dict(self, **kwargs):
        """Serialize message to dictionary"""
        return super().model_dump(**kwargs)


class ChatMessage(BaseMessage):
    """Chat message with text content"""
    type: Literal["chat"] = "chat"
    text: str
    user_id: int


class JoinRoomMessage(BaseMessage):
    """Message for joining a room"""
    type: Literal["join_room"] = "join_room"
    room_id: str
    user_name: str


class GameActionMessage(BaseMessage):
    """Game action message with coordinates"""
    type: Literal["game_action"] = "game_action"
    action: str
    coordinates: Tuple[int, int] 