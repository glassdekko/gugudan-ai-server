"""Kakao OAuth provider implementation."""

from app.auth.application.port.oauth_provider_port import OAuthUserInfo
from app.auth.infrastructure.oauth.base import BaseOAuthProvider
from config.settings import settings


class KakaoOAuthProvider(BaseOAuthProvider):
    """Kakao OAuth 2.0 provider.

    Implements OAuth authorization code flow for Kakao Sign-In.
    Uses Kakao Login API for authentication.
    """

    AUTHORIZE_URL = "https://kauth.kakao.com/oauth/authorize"
    TOKEN_URL = "https://kauth.kakao.com/oauth/token"
    USERINFO_URL = "https://kapi.kakao.com/v2/user/me"
    SCOPES = ["profile_nickname", "account_email"]

    def __init__(self):
        """Initialize Kakao OAuth provider with settings."""
        super().__init__(
            client_id=settings.KAKAO_CLIENT_ID,
            client_secret=settings.KAKAO_CLIENT_SECRET,
            redirect_uri=settings.KAKAO_REDIRECT_URI,
        )

    @property
    def provider_name(self) -> str:
        """Get the provider name."""
        return "kakao"

    def _get_extra_auth_params(self) -> dict:
        """Get extra authorization parameters for Kakao."""
        return {
            "prompt": "login",  # Always show login screen
        }

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        """Get user info from Kakao.

        Kakao returns user info in a nested structure:
        {
            "id": 12345,
            "kakao_account": {
                "email": "user@example.com",
                "profile": {
                    "nickname": "User Name"
                }
            }
        }
        """
        data = await self._fetch_user_info(access_token)

        kakao_account = data.get("kakao_account", {})
        profile = kakao_account.get("profile", {})

        email = kakao_account.get("email", "")
        nickname = profile.get("nickname", "")

        # Fallback to kakao_id if no nickname
        if not nickname:
            nickname = f"kakao_{data.get('id', '')}"

        return OAuthUserInfo(
            email=email,
            name=nickname,
            picture=profile.get("profile_image_url"),
            provider=self.provider_name,
        )
