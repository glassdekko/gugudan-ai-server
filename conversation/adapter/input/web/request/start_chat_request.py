from pydantic import BaseModel, Field
from typing import Optional


class StartChatRequest(BaseModel):
    category: str = Field(..., example="LOVE")
    division: str = Field(..., example="CONSULT")
    title: Optional[str] = Field(None, example="연애 상담")
