"""Response schemas for auth adapter."""

from app.auth.adapter.input.web.response.user_response import UserResponse
from app.auth.adapter.input.web.response.auth_status_response import AuthStatusResponse
from app.auth.adapter.input.web.response.logout_response import LogoutResponse
from app.auth.adapter.input.web.response.providers_response import OAuthProvidersResponse
from app.auth.adapter.input.web.response.error_response import ErrorResponse

__all__ = [
    "UserResponse",
    "AuthStatusResponse",
    "LogoutResponse",
    "OAuthProvidersResponse",
    "ErrorResponse",
]
