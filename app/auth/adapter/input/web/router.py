"""Auth API router - OAuth endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse

from app.auth.adapter.input.web.dependencies import (
    get_account_usecase,
    get_auth_usecase,
    get_current_session,
    get_optional_session,
    verify_csrf,
)
from app.auth.adapter.input.web.response import (
    AuthStatusResponse,
    LogoutResponse,
    OAuthProvidersResponse,
    UserResponse,
)
from app.account.application.usecase.account_usecase import AccountUseCase
from app.auth.application.usecase.auth_usecase import AuthUseCase
from app.auth.domain.entity.session import Session
from app.common.domain.exceptions import UnsupportedOAuthProviderException
from config.settings import settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/providers", response_model=OAuthProvidersResponse)
async def get_providers(
    auth_usecase: AuthUseCase = Depends(get_auth_usecase),
) -> OAuthProvidersResponse:
    """Get list of supported OAuth providers."""
    providers = auth_usecase.get_supported_providers()
    return OAuthProvidersResponse(providers=providers)


@router.get("/status", response_model=AuthStatusResponse)
async def get_auth_status(
    session: Session | None = Depends(get_optional_session),
    account_usecase: AccountUseCase = Depends(get_account_usecase),
) -> AuthStatusResponse:
    """Check authentication status.

    Returns authentication status and user info if authenticated.
    """
    if not session:
        return AuthStatusResponse(is_authenticated=False)

    account = account_usecase.get_account_by_id(session.account_id)

    if not account:
        return AuthStatusResponse(is_authenticated=False)

    return AuthStatusResponse(
        is_authenticated=True,
        user=UserResponse.from_entity(account),
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user(
    session: Session = Depends(get_current_session),
    account_usecase: AccountUseCase = Depends(get_account_usecase),
) -> UserResponse:
    """Get current authenticated user."""
    account = account_usecase.get_account_by_id(session.account_id)

    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Account not found",
        )

    return UserResponse.from_entity(account)


@router.post("/logout", response_model=LogoutResponse)
async def logout(
    response: Response,
    session: Session = Depends(get_current_session),
    _csrf_valid: bool = Depends(verify_csrf),
    auth_usecase: AuthUseCase = Depends(get_auth_usecase),
) -> LogoutResponse:
    """Logout - destroy session.

    Requires valid session and CSRF token.
    """
    auth_usecase.logout(session.session_id)

    # Clear cookies
    response.delete_cookie("session_id")
    response.delete_cookie("csrf_token")

    return LogoutResponse()


# Dynamic provider routes must come AFTER specific routes
@router.get("/{provider}")
async def oauth_login(
    provider: str,
    auth_usecase: AuthUseCase = Depends(get_auth_usecase),
) -> RedirectResponse:
    """Initiate OAuth login flow.

    Redirects user to OAuth provider's authorization page.
    """
    try:
        url, state = auth_usecase.initiate_oauth(provider)

        # Create redirect response
        response = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)

        # Store state in cookie for CSRF protection on callback
        response.set_cookie(
            key="oauth_state",
            value=state,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite="lax",
            max_age=600,  # 10 minutes
        )

        return response

    except UnsupportedOAuthProviderException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e.message),
        )


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: str,
    state: str,
    request: Request,
    auth_usecase: AuthUseCase = Depends(get_auth_usecase),
) -> RedirectResponse:
    """Handle OAuth callback.

    Validates state, exchanges code for token, creates session.
    """

    # Verify state matches cookie (CSRF protection)
    cookie_state = request.cookies.get("oauth_state")

    if not cookie_state or cookie_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter",
        )

    try:
        # Handle OAuth callback
        session, csrf_token = await auth_usecase.handle_callback(provider, code)

        # Redirect to frontend
        response = RedirectResponse(
            url=settings.FRONTEND_URL,
            status_code=status.HTTP_302_FOUND,
        )

        # Set session cookie (HttpOnly - not accessible by JS)
        response.set_cookie(
            key="session_id",
            value=session.session_id,
            httponly=True,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            max_age=settings.SESSION_TTL_SECONDS,
        )

        # Set CSRF token cookie (readable by JS for header)
        response.set_cookie(
            key="csrf_token",
            value=csrf_token,
            httponly=False,  # Must be readable by JavaScript
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
            max_age=settings.SESSION_TTL_SECONDS,
        )

        # Delete oauth_state cookie
        response.delete_cookie("oauth_state")

        return response

    except UnsupportedOAuthProviderException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e.message),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth callback failed: {str(e)}",
        )
