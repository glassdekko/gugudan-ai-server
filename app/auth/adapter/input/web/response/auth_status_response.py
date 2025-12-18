"""Auth status response schema."""

from typing import Optional

from pydantic import BaseModel

from app.auth.adapter.input.web.response.user_response import UserResponse


class AuthStatusResponse(BaseModel):
    """Response for authentication status check."""

    is_authenticated: bool
    user: Optional[UserResponse] = None
