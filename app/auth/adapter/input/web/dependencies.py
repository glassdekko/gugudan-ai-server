"""Auth API dependencies - FastAPI dependency injection."""

from typing import Generator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession

from app.account.application.usecase.account_usecase import AccountUseCase
from app.auth.application.usecase.csrf_usecase import CSRFUseCase
from app.auth.application.usecase.auth_usecase import AuthUseCase
from app.auth.application.usecase.session_usecase import SessionUseCase
from app.auth.domain.entity.session import Session
from app.auth.infrastructure.cache.session_repository_impl import SessionRepositoryImpl
from app.account.infrastructure.repository.account_repository_impl import AccountRepositoryImpl
from config.database.session import SessionLocal


def get_db() -> Generator[DBSession, None, None]:
    """Get database session dependency."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_session_repository() -> SessionRepositoryImpl:
    """Get session repository dependency."""
    return SessionRepositoryImpl()


def get_account_repository(
    db: DBSession = Depends(get_db),
) -> AccountRepositoryImpl:
    """Get account repository dependency."""
    return AccountRepositoryImpl(db)


def get_csrf_usecase() -> CSRFUseCase:
    """Get CSRF usecase dependency."""
    return CSRFUseCase()


def get_session_usecase(
    session_repo: SessionRepositoryImpl = Depends(get_session_repository),
) -> SessionUseCase:
    """Get session usecase dependency."""
    return SessionUseCase(session_repo)


def get_account_usecase(
    account_repo: AccountRepositoryImpl = Depends(get_account_repository),
) -> AccountUseCase:
    """Get account usecase dependency."""
    return AccountUseCase(account_repo)


def get_auth_usecase(
    session_usecase: SessionUseCase = Depends(get_session_usecase),
    csrf_usecase: CSRFUseCase = Depends(get_csrf_usecase),
    account_usecase: AccountUseCase = Depends(get_account_usecase),
) -> AuthUseCase:
    """Get auth usecase dependency."""
    return AuthUseCase(session_usecase, csrf_usecase, account_usecase)


def get_current_session(
    request: Request,
    session_usecase: SessionUseCase = Depends(get_session_usecase),
) -> Session:
    """Get current session from cookie.

    Validates the session and returns it if valid.

    Raises:
        HTTPException: 401 if not authenticated or session invalid.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    session = session_usecase.validate_session(session_id)

    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return session


def get_optional_session(
    request: Request,
    session_usecase: SessionUseCase = Depends(get_session_usecase),
) -> Session | None:
    """Get current session if available, None otherwise.

    Unlike get_current_session, this doesn't raise an error if not authenticated.
    """
    session_id = request.cookies.get("session_id")

    if not session_id:
        return None

    return session_usecase.validate_session(session_id)


def verify_csrf(
    request: Request,
    csrf_usecase: CSRFUseCase = Depends(get_csrf_usecase),
) -> bool:
    """Verify CSRF token using Double Submit Cookie pattern.

    Raises:
        HTTPException: 403 if CSRF validation fails.
    """
    cookie_token = request.cookies.get("csrf_token")
    header_token = request.headers.get("X-CSRF-Token")

    if not csrf_usecase.validate_token(cookie_token, header_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token validation failed",
        )

    return True
