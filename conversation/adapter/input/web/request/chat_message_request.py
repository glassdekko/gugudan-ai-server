from pydantic import BaseModel, Field


class ChatMessageRequest(BaseModel):
    room_id: str = Field(..., example="uuid")
    message: str = Field(..., min_length=1)
    contents_type: str = Field(default="TEXT")
