"""Session value object - Domain model for user sessions."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
import secrets


def generate_session_id() -> str:
    """Generate a cryptographically secure session ID."""
    return secrets.token_urlsafe(32)


@dataclass
class Session:
    """Value object representing a user session.

    Sessions are stored server-side (in Redis) and identified by a session_id
    stored in an HttpOnly cookie on the client.
    """

    account_id: int
    session_id: str = field(default_factory=generate_session_id)
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    csrf_token: Optional[str] = None

    def __post_init__(self):
        """Set default expiration if not provided."""
        if self.expires_at is None:
            # Default 24 hours expiration
            self.expires_at = self.created_at + timedelta(hours=24)

    def is_expired(self) -> bool:
        """Check if the session has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def is_valid(self) -> bool:
        """Check if the session is valid (not expired)."""
        return not self.is_expired()

    def extend(self, hours: int = 24) -> None:
        """Extend the session expiration time."""
        self.expires_at = datetime.now() + timedelta(hours=hours)

    def to_dict(self) -> dict:
        """Convert session to dictionary for serialization."""
        return {
            "session_id": self.session_id,
            "account_id": self.account_id,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "csrf_token": self.csrf_token,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Session":
        """Create session from dictionary."""
        return cls(
            session_id=data["session_id"],
            account_id=data["account_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            csrf_token=data.get("csrf_token"),
        )
