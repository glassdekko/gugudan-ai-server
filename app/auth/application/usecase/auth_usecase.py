"""Auth usecase - OAuth authentication orchestration."""

import secrets
from typing import Optional, Tuple, Union

from app.account.application.usecase.account_usecase import AccountUseCase
from app.auth.application.port.jwt_token_port import JWTTokenPort, TokenPair, TokenPayload
from app.auth.application.usecase.csrf_usecase import CSRFUseCase
from app.auth.application.usecase.session_usecase import SessionUseCase
from app.auth.domain.entity.session import Session
from app.auth.domain.entity.sso_login_type import SSOLoginType
from app.auth.infrastructure.oauth.factory import OAuthProviderFactory


class AuthUseCase:
    """UseCase for authentication orchestration.

    Coordinates the OAuth flow, JWT token creation, and account management.
    Supports both session-based and JWT-based authentication.
    """

    def __init__(
        self,
        session_usecase: SessionUseCase,
        csrf_usecase: CSRFUseCase,
        account_usecase: AccountUseCase,
        jwt_service: Optional[JWTTokenPort] = None,
    ):
        """Initialize auth usecase.

        Args:
            session_usecase: UseCase for session management.
            csrf_usecase: UseCase for CSRF token management.
            account_usecase: UseCase for account management.
            jwt_service: Service for JWT token operations (optional).
        """
        self._session_usecase = session_usecase
        self._csrf_usecase = csrf_usecase
        self._account_usecase = account_usecase
        self._jwt_service = jwt_service

    def initiate_oauth(self, provider_name: str) -> Tuple[str, str]:
        """Initiate OAuth flow by getting authorization URL.

        Args:
            provider_name: Name of OAuth provider (google, kakao, naver).

        Returns:
            Tuple of (authorization_url, state_token).

        Raises:
            UnsupportedOAuthProviderException: If provider is not supported.
        """
        # Validate provider using SSOLoginType enum
        sso_type = SSOLoginType.from_string(provider_name)
        provider = OAuthProviderFactory.get_provider(sso_type.value)
        state = secrets.token_urlsafe(32)
        url = provider.get_authorization_url(state)
        return url, state

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
    ) -> Tuple[Session, str]:
        """Handle OAuth callback and create session (legacy method).

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

    async def handle_callback_jwt(
        self,
        provider_name: str,
        code: str,
    ) -> TokenPair:
        """Handle OAuth callback and create JWT token.

        This is the new JWT-based authentication method.

        Args:
            provider_name: Name of OAuth provider.
            code: Authorization code from OAuth provider.

        Returns:
            TokenPair containing access token and CSRF token.

        Raises:
            OAuthException: If OAuth process fails.
            ValueError: If JWT service is not configured.
        """
        if self._jwt_service is None:
            raise ValueError("JWT service is not configured")

        # Validate provider using SSOLoginType enum
        sso_type = SSOLoginType.from_string(provider_name)
        provider = OAuthProviderFactory.get_provider(sso_type.value)

        # Exchange code for access token
        access_token = await provider.exchange_code_for_token(code)

        # Get user info from provider
        user_info = await provider.get_user_info(access_token)

        # Get or create account
        account = self._account_usecase.get_or_create_account(
            email=user_info.email,
            nickname=user_info.name,
        )

        # Create JWT token pair
        token_pair = self._jwt_service.create_token(
            account_id=account.id,
            provider=sso_type.value,
        )

        return token_pair

    def validate_jwt(self, token: str) -> Optional[TokenPayload]:
        """Validate a JWT token.

        Args:
            token: The JWT token string.

        Returns:
            TokenPayload if valid, None otherwise.
        """
        if self._jwt_service is None:
            return None
        return self._jwt_service.validate_token(token)

    def validate_jwt_csrf(self, token: str, csrf_token: str) -> bool:
        """Validate JWT CSRF token.

        Args:
            token: The JWT token string.
            csrf_token: The CSRF token to validate.

        Returns:
            True if CSRF tokens match, False otherwise.
        """
        if self._jwt_service is None:
            return False
        return self._jwt_service.validate_csrf(token, csrf_token)

    def refresh_jwt(self, token: str) -> Optional[TokenPair]:
        """Refresh a JWT token.

        Args:
            token: The existing JWT token.

        Returns:
            New TokenPair if refresh successful, None otherwise.
        """
        if self._jwt_service is None:
            return None
        return self._jwt_service.refresh_token(token)

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
        return SSOLoginType.get_supported_providers()

    def get_account_by_id(self, account_id: int):
        """Get account by ID.

        Args:
            account_id: The account ID.

        Returns:
            The account if found.
        """
        return self._account_usecase.get_account_by_id(account_id)
