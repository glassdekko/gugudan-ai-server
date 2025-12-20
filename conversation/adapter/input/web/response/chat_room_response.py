from pydantic import BaseModel
from datetime import datetime


class ChatRoomResponse(BaseModel):
    room_id: str
    title: str
    status: str
    created_at: datetime
