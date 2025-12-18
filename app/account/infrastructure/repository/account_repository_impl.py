"""Account repository implementation using SQLAlchemy."""

from typing import Optional

from sqlalchemy.orm import Session as DBSession

from app.account.domain.entity.account import Account
from app.account.application.port.account_repository_port import AccountRepositoryPort
from app.account.infrastructure.orm.account_model import AccountModel


class AccountRepositoryImpl(AccountRepositoryPort):
    """SQLAlchemy implementation of AccountRepositoryPort.

    This adapter implements the application port using SQLAlchemy for persistence.
    """

    def __init__(self, db_session: DBSession):
        """Initialize with a database session.

        Args:
            db_session: SQLAlchemy database session.
        """
        self._session = db_session

    def find_by_id(self, account_id: int) -> Optional[Account]:
        """Find an account by its ID."""
        model = (
            self._session.query(AccountModel)
            .filter(AccountModel.id == account_id)
            .first()
        )
        return self._to_entity(model) if model else None

    def find_by_email(self, email: str) -> Optional[Account]:
        """Find an account by email address."""
        model = (
            self._session.query(AccountModel)
            .filter(AccountModel.email == email)
            .first()
        )
        return self._to_entity(model) if model else None

    def save(self, account: Account) -> Account:
        """Save an account (create or update)."""
        if account.is_new():
            # Create new account
            model = self._to_model(account)
            self._session.add(model)
            self._session.commit()
            self._session.refresh(model)
            return self._to_entity(model)
        else:
            # Update existing account
            model = (
                self._session.query(AccountModel)
                .filter(AccountModel.id == account.id)
                .first()
            )
            if model:
                model.email = account.email
                model.nickname = account.nickname
                model.terms_agreed = account.terms_agreed
                model.terms_agreed_at = account.terms_agreed_at
                self._session.commit()
                self._session.refresh(model)
                return self._to_entity(model)
            else:
                # Account not found, create new
                return self.save(Account(
                    email=account.email,
                    nickname=account.nickname,
                    terms_agreed=account.terms_agreed,
                    terms_agreed_at=account.terms_agreed_at,
                ))

    def exists_by_email(self, email: str) -> bool:
        """Check if an account exists with the given email."""
        return (
            self._session.query(AccountModel)
            .filter(AccountModel.email == email)
            .first()
            is not None
        )

    @staticmethod
    def _to_entity(model: AccountModel) -> Account:
        """Convert SQLAlchemy model to domain entity."""
        return Account(
            id=model.id,
            email=model.email,
            nickname=model.nickname,
            terms_agreed=model.terms_agreed,
            terms_agreed_at=model.terms_agreed_at,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    @staticmethod
    def _to_model(entity: Account) -> AccountModel:
        """Convert domain entity to SQLAlchemy model."""
        return AccountModel(
            id=entity.id,
            email=entity.email,
            nickname=entity.nickname,
            terms_agreed=entity.terms_agreed,
            terms_agreed_at=entity.terms_agreed_at,
        )
