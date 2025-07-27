"""
Type definitions for aiows
"""

from datetime import datetime
from typing import Literal, Tuple
from pydantic import BaseModel, Field, field_validator

from ..validators import (
    validate_safe_text, validate_username, validate_room_id, 
    validate_game_action, validate_user_id, validate_coordinates
)


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
    
    @field_validator('text')
    @classmethod
    def validate_text_field(cls, v):
        return validate_safe_text(cls, v)
    
    @field_validator('user_id', mode='before')
    @classmethod
    def validate_user_id_field(cls, v):
        return validate_user_id(cls, v)


class JoinRoomMessage(BaseMessage):
    """Message for joining a room"""
    type: Literal["join_room"] = "join_room"
    room_id: str
    user_name: str
    
    @field_validator('room_id')
    @classmethod
    def validate_room_id_field(cls, v):
        return validate_room_id(cls, v)
    
    @field_validator('user_name')
    @classmethod
    def validate_user_name_field(cls, v):
        return validate_username(cls, v)


class GameActionMessage(BaseMessage):
    """Game action message with coordinates"""
    type: Literal["game_action"] = "game_action"
    action: str
    coordinates: Tuple[int, int]
    
    @field_validator('action')
    @classmethod
    def validate_action_field(cls, v):
        return validate_game_action(cls, v)
    
    @field_validator('coordinates')
    @classmethod
    def validate_coordinates_field(cls, v):
        return validate_coordinates(cls, v)