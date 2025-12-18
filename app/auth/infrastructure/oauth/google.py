"""Google OAuth provider implementation."""

from app.auth.application.port.oauth_provider_port import OAuthUserInfo
from app.auth.infrastructure.oauth.base import BaseOAuthProvider
from config.settings import settings


class GoogleOAuthProvider(BaseOAuthProvider):
    """Google OAuth 2.0 provider.

    Implements OAuth authorization code flow for Google Sign-In.
    Uses OpenID Connect for user info.
    """

    AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
    SCOPES = ["openid", "email", "profile"]

    def __init__(self):
        """Initialize Google OAuth provider with settings."""
        super().__init__(
            client_id=settings.GOOGLE_CLIENT_ID,
            client_secret=settings.GOOGLE_CLIENT_SECRET,
            redirect_uri=settings.GOOGLE_REDIRECT_URI,
        )

    @property
    def provider_name(self) -> str:
        """Get the provider name."""
        return "google"

    def _get_extra_auth_params(self) -> dict:
        """Get extra authorization parameters for Google."""
        return {
            "access_type": "offline",  # Get refresh token
            "prompt": "consent",  # Always show consent screen
        }

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user info from Google."""
        data = await self._fetch_user_info(access_token)

        return OAuthUserInfo(
            email=data.get("email", ""),
            name=data.get("name", data.get("email", "").split("@")[0]),
            picture=data.get("picture"),
            provider=self.provider_name,
        )
