from pydantic import BaseModel, Field


class EndChatRequest(BaseModel):
    room_id: str = Field(..., example="uuid")
