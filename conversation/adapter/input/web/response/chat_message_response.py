from pydantic import BaseModel
from datetime import datetime


class ChatMessageResponse(BaseModel):
    role: str
    content: str
    created_at: datetime
