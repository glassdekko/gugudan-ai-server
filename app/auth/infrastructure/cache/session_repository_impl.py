"""Session repository implementation using Redis."""

import json
from typing import Optional

import redis

from app.auth.application.port.session_repository_port import SessionRepositoryPort
from app.auth.domain.entity.session import Session
from config.redis_config import get_redis
from config.settings import settings


class SessionRepositoryImpl(SessionRepositoryPort):
    """Redis implementation of SessionRepositoryPort.

    Sessions are stored in Redis with TTL-based expiration.
    Key format: session:{session_id}
    """

    KEY_PREFIX = "session:"

    def __init__(
        self,
        redis_client: Optional[redis.Redis] = None,
        ttl_seconds: Optional[int] = None,
    ):
        """Initialize with Redis client and TTL.

        Args:
            redis_client: Redis client instance. Uses default if not provided.
            ttl_seconds: Session TTL in seconds. Uses settings default if not provided.
        """
        self._redis = redis_client or get_redis()
        self._ttl = ttl_seconds or settings.SESSION_TTL_SECONDS

    def _make_key(self, session_id: str) -> str:
        """Create Redis key for session."""
        return f"{self.KEY_PREFIX}{session_id}"

    def save(self, session: Session) -> None:
        """Save a session to Redis with TTL."""
        key = self._make_key(session.session_id)
        data = json.dumps(session.to_dict())
        self._redis.setex(key, self._ttl, data)

    def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find a session by its ID."""
        key = self._make_key(session_id)
        data = self._redis.get(key)

        if data is None:
            return None

        try:
            session_dict = json.loads(data)
            session = Session.from_dict(session_dict)

            # Double-check expiration (Redis TTL + session expiration)
            if session.is_expired():
                self.delete(session_id)
                return None

            return session
        except (json.JSONDecodeError, KeyError, ValueError):
            # Invalid session data, clean up
            self.delete(session_id)
            return None

    def delete(self, session_id: str) -> None:
        """Delete a session from Redis."""
        key = self._make_key(session_id)
        self._redis.delete(key)

    def extend_ttl(self, session_id: str, ttl_seconds: int) -> bool:
        """Extend the TTL of a session."""
        key = self._make_key(session_id)

        # Check if session exists
        if not self._redis.exists(key):
            return False

        # Update session expiration and save
        session = self.find_by_id(session_id)
        if session:
            session.extend(hours=ttl_seconds // 3600)
            self.save(session)
            return True

        return False
