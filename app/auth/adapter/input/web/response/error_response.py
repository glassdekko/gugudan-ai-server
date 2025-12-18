"""Error response schema."""

from typing import Optional

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    code: Optional[str] = None
