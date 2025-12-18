"""Session usecase - Session management."""

from typing import Optional

from app.auth.application.port.session_repository_port import SessionRepositoryPort
from app.auth.domain.entity.session import Session
from config.settings import settings


class SessionUseCase:
    """UseCase for session management.

    Handles creation, validation, and destruction of user sessions.
    Sessions are stored server-side in Redis.
    """

    def __init__(self, session_repository: SessionRepositoryPort):
        """Initialize session usecase.

        Args:
            session_repository: Repository for session persistence.
        """
        self._repository = session_repository

    def create_session(
        self,
        account_id: int,
        csrf_token: Optional[str] = None,
    ) -> Session:
        """Create a new session for an account.

        Args:
            account_id: ID of the account to create session for.
            csrf_token: Optional CSRF token to associate with session.

        Returns:
            The created session.
        """
        session = Session(
            account_id=account_id,
            csrf_token=csrf_token,
        )
        self._repository.save(session)
        return session

    def validate_session(self, session_id: str) -> Optional[Session]:
        """Validate a session by its ID.

        Args:
            session_id: The session ID to validate.

        Returns:
            The session if valid, None otherwise.
        """
        session = self._repository.find_by_id(session_id)

        if session is None:
            return None

        if not session.is_valid():
            self._repository.delete(session_id)
            return None

        return session

    def destroy_session(self, session_id: str) -> None:
        """Destroy (logout) a session.

        Args:
            session_id: The session ID to destroy.
        """
        self._repository.delete(session_id)

    def refresh_session(self, session_id: str) -> Optional[Session]:
        """Refresh a session's expiration time.

        Args:
            session_id: The session ID to refresh.

        Returns:
            The refreshed session if found, None otherwise.
        """
        session = self._repository.find_by_id(session_id)

        if session is None or not session.is_valid():
            return None

        # Extend session
        session.extend(hours=settings.SESSION_TTL_SECONDS // 3600)
        self._repository.save(session)

        return session

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID without validation side effects.

        Args:
            session_id: The session ID to get.

        Returns:
            The session if found, None otherwise.
        """
        return self._repository.find_by_id(session_id)
