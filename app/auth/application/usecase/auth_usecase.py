"""Auth usecase - OAuth authentication orchestration."""

import secrets
from typing import Tuple

from app.account.application.usecase.account_usecase import AccountUseCase
from app.auth.application.usecase.csrf_usecase import CSRFUseCase
from app.auth.application.usecase.session_usecase import SessionUseCase
from app.auth.domain.entity.session import Session
from app.auth.infrastructure.oauth.factory import OAuthProviderFactory


class AuthUseCase:
    """UseCase for authentication orchestration.

    Coordinates the OAuth flow, session creation, and CSRF token generation.
    """

    def __init__(
        self,
        session_usecase: SessionUseCase,
        csrf_usecase: CSRFUseCase,
        account_usecase: AccountUseCase,
    ):
        """Initialize auth usecase.

        Args:
            session_usecase: UseCase for session management.
            csrf_usecase: UseCase for CSRF token management.
            account_usecase: UseCase for account management.
        """
        self._session_usecase = session_usecase
        self._csrf_usecase = csrf_usecase
        self._account_usecase = account_usecase

    def initiate_oauth(self, provider_name: str) -> Tuple[str, str]:
        """Initiate OAuth flow by getting authorization URL.

        Args:
            provider_name: Name of OAuth provider (google, kakao, naver).

        Returns:
            Tuple of (authorization_url, state_token).

        Raises:
            UnsupportedOAuthProviderException: If provider is not supported.
        """
        provider = OAuthProviderFactory.get_provider(provider_name)
        state = secrets.token_urlsafe(32)
        url = provider.get_authorization_url(state)
        return url, state

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
    ) -> Tuple[Session, str]:
        """Handle OAuth callback and create session.

        Args:
            provider_name: Name of OAuth provider.
            code: Authorization code from OAuth provider.

        Returns:
            Tuple of (session, csrf_token).

        Raises:
            OAuthException: If OAuth process fails.
        """
        provider = OAuthProviderFactory.get_provider(provider_name)

        # Exchange code for access token
        access_token = await provider.exchange_code_for_token(code)

        # Get user info from provider
        user_info = await provider.get_user_info(access_token)

        # Get or create account
        account = self._account_usecase.get_or_create_account(
            email=user_info.email,
            nickname=user_info.name,
        )

        # Generate CSRF token
        csrf_token = self._csrf_usecase.generate_token()

        # Create session with CSRF token
        session = self._session_usecase.create_session(
            account_id=account.id,
            csrf_token=csrf_token,
        )

        return session, csrf_token

    def logout(self, session_id: str) -> None:
        """Logout by destroying session.

        Args:
            session_id: The session ID to destroy.
        """
        self._session_usecase.destroy_session(session_id)

    def validate_session(self, session_id: str) -> Session | None:
        """Validate a session.

        Args:
            session_id: The session ID to validate.

        Returns:
            The session if valid, None otherwise.
        """
        return self._session_usecase.validate_session(session_id)

    def get_supported_providers(self) -> list[str]:
        """Get list of supported OAuth providers.

        Returns:
            List of provider names.
        """
        return OAuthProviderFactory.get_supported_providers()
