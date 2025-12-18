"""Account entity - Domain model for user accounts."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Account:
    """Domain entity representing a user account.

    This is a pure domain object with no framework dependencies.
    """

    email: str
    nickname: str
    id: Optional[int] = None
    terms_agreed: bool = False
    terms_agreed_at: Optional[datetime] = None
    created_at: Optional[datetime] = field(default_factory=datetime.now)
    updated_at: Optional[datetime] = field(default_factory=datetime.now)

    def __post_init__(self):
        """Validate entity on creation."""
        if not self.email:
            raise ValueError("Email is required")
        if not self.nickname:
            raise ValueError("Nickname is required")
        if "@" not in self.email:
            raise ValueError("Invalid email format")

    def agree_to_terms(self) -> None:
        """Mark that user has agreed to terms of service."""
        self.terms_agreed = True
        self.terms_agreed_at = datetime.now()
        self.updated_at = datetime.now()

    def update_nickname(self, nickname: str) -> None:
        """Update the user's nickname."""
        if not nickname:
            raise ValueError("Nickname cannot be empty")
        self.nickname = nickname
        self.updated_at = datetime.now()

    def is_new(self) -> bool:
        """Check if this is a new account (not yet persisted)."""
        return self.id is None
