"""OAuth provider port - Interface for OAuth provider adapters."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class OAuthUserInfo:
    """User information retrieved from OAuth provider."""

    email: str
    name: str
    picture: Optional[str] = None
    provider: Optional[str] = None


class OAuthProviderPort(ABC):
    """Port (interface) for OAuth provider adapters.

    Each OAuth provider (Google, Kakao, Naver) implements this interface.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the name of this OAuth provider."""
        pass

    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        """Get the URL to redirect user to for OAuth authorization.

        Args:
            state: CSRF state token to include in the request.

        Returns:
            The authorization URL to redirect the user to.
        """
        pass

    @abstractmethod
    async def exchange_code_for_token(self, code: str) -> str:
        """Exchange authorization code for access token.

        Args:
            code: The authorization code from OAuth callback.

        Returns:
            The access token.

        Raises:
            OAuthException: If token exchange fails.
        """
        pass

    @abstractmethod
    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user information using access token.

        Args:
            access_token: The OAuth access token.

        Returns:
            User information from the OAuth provider.

        Raises:
            OAuthException: If fetching user info fails.
        """
        pass
