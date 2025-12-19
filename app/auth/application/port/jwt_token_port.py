"""JWT Token Port - Interface for JWT token operations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class TokenPayload:
    """JWT Token payload data."""

    account_id: int
    encrypted_key: str  # AES encrypted user-specific UUID
    encrypted_key_iv: str  # IV used for encryption
    csrf_token: str
    provider: str
    exp: datetime
    iat: datetime


@dataclass
class TokenPair:
    """Access and CSRF token pair."""

    access_token: str
    csrf_token: str
    expires_at: datetime


class JWTTokenPort(ABC):
    """Port for JWT token operations.

    Defines the interface for creating and validating JWT tokens.
    """

    @abstractmethod
    def create_token(
        self,
        account_id: int,
        provider: str,
    ) -> TokenPair:
        """Create a new JWT token pair.

        Args:
            account_id: The user's account ID.
            provider: The SSO provider used for authentication.

        Returns:
            TokenPair containing access token and CSRF token.
        """
        pass

    @abstractmethod
    def validate_token(self, token: str) -> Optional[TokenPayload]:
        """Validate a JWT token and extract payload.

        Args:
            token: The JWT token string.

        Returns:
            TokenPayload if valid, None if invalid or expired.
        """
        pass

    @abstractmethod
    def validate_csrf(self, token: str, csrf_token: str) -> bool:
        """Validate that the CSRF token matches the one in the JWT.

        Args:
            token: The JWT token string.
            csrf_token: The CSRF token to validate.

        Returns:
            True if CSRF tokens match, False otherwise.
        """
        pass

    @abstractmethod
    def refresh_token(self, token: str) -> Optional[TokenPair]:
        """Refresh an existing token if still valid.

        Args:
            token: The existing JWT token.

        Returns:
            New TokenPair if refresh successful, None otherwise.
        """
        pass
