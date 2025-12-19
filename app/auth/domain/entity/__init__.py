"""Auth domain entities."""

from app.auth.domain.entity.session import Session
from app.auth.domain.entity.sso_login_type import SSOLoginType

__all__ = ["Session", "SSOLoginType"]
