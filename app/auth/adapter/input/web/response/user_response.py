"""User response schema."""

from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.account.domain.entity.account import Account


class UserResponse(BaseModel):
    """Response schema for user/account data."""

    id: int
    email: EmailStr
    nickname: str
    terms_agreed: bool
    created_at: datetime

    class Config:
        from_attributes = True

    @classmethod
    def from_entity(cls, account: Account) -> "UserResponse":
        """Create response from domain entity."""
        return cls(
            id=account.id,
            email=account.email,
            nickname=account.nickname,
            terms_agreed=account.terms_agreed,
            created_at=account.created_at,
        )
