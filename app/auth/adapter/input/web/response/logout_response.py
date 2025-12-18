"""Logout response schema."""

from pydantic import BaseModel


class LogoutResponse(BaseModel):
    """Response for logout endpoint."""

    message: str = "Logged out successfully"
