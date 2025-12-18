"""Session repository port - Interface for session persistence."""

from abc import ABC, abstractmethod
from typing import Optional

from app.auth.domain.entity.session import Session


class SessionRepositoryPort(ABC):
    """Port (interface) for session repository.

    Sessions are stored server-side (e.g., in Redis) with TTL-based expiration.
    """

    @abstractmethod
    def save(self, session: Session) -> None:
        """Save a session.

        Args:
            session: The session to save.
        """
        pass

    @abstractmethod
    def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find a session by its ID.

        Args:
            session_id: The session's unique identifier.

        Returns:
            The Session if found and not expired, None otherwise.
        """
        pass

    @abstractmethod
    def delete(self, session_id: str) -> None:
        """Delete a session.

        Args:
            session_id: The session's unique identifier.
        """
        pass

    @abstractmethod
    def extend_ttl(self, session_id: str, ttl_seconds: int) -> bool:
        """Extend the TTL of a session.

        Args:
            session_id: The session's unique identifier.
            ttl_seconds: New TTL in seconds.

        Returns:
            True if session was found and extended, False otherwise.
        """
        pass
