"""User response schema."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr

from app.account.domain.entity.account import Account


class UserResponse(BaseModel):
    """Response schema for user/account data."""

    id: int
    email: EmailStr
    nickname: str
    terms_agreed: bool
    created_at: datetime
    # New fields
    role: str
    plan: str
    plan_started_at: Optional[datetime] = None
    plan_ends_at: Optional[datetime] = None
    status: str
    gender: Optional[str] = None
    mbti: Optional[str] = None

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
            role=account.role.value,
            plan=account.plan.value,
            plan_started_at=account.plan_started_at,
            plan_ends_at=account.plan_ends_at,
            gender=account.gender.value if account.gender else None,
            mbti=account.mbti.value if account.mbti else None,
            status=account.status.value,
        )
