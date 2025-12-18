"""Account usecase - Account management."""

from typing import Optional

from app.account.domain.entity.account import Account
from app.account.application.port.account_repository_port import AccountRepositoryPort
from app.common.domain.exceptions import AccountNotFoundException


class AccountUseCase:
    """UseCase for account management.

    Handles account creation, retrieval, and updates.
    """

    def __init__(self, account_repository: AccountRepositoryPort):
        """Initialize account usecase.

        Args:
            account_repository: Repository for account persistence.
        """
        self._repository = account_repository

    def get_or_create_account(self, email: str, nickname: str) -> Account:
        """Get an existing account by email or create a new one.

        This is the primary method used during OAuth login.

        Args:
            email: User's email address.
            nickname: User's display name.

        Returns:
            The existing or newly created account.
        """
        existing = self._repository.find_by_email(email)

        if existing:
            return existing

        # Create new account
        account = Account(
            email=email,
            nickname=nickname,
        )
        return self._repository.save(account)

    def get_account_by_id(self, account_id: int) -> Optional[Account]:
        """Get an account by its ID.

        Args:
            account_id: The account's unique identifier.

        Returns:
            The account if found, None otherwise.
        """
        return self._repository.find_by_id(account_id)

    def get_account_by_email(self, email: str) -> Optional[Account]:
        """Get an account by email address.

        Args:
            email: The email address to search for.

        Returns:
            The account if found, None otherwise.
        """
        return self._repository.find_by_email(email)

    def update_account(self, account: Account) -> Account:
        """Update an account.

        Args:
            account: The account with updated fields.

        Returns:
            The updated account.

        Raises:
            AccountNotFoundException: If account doesn't exist.
        """
        if account.id is None:
            raise ValueError("Cannot update account without ID")

        existing = self._repository.find_by_id(account.id)
        if not existing:
            raise AccountNotFoundException(account.id)

        return self._repository.save(account)

    def agree_to_terms(self, account_id: int) -> Account:
        """Mark an account as having agreed to terms.

        Args:
            account_id: The account's unique identifier.

        Returns:
            The updated account.

        Raises:
            AccountNotFoundException: If account doesn't exist.
        """
        account = self._repository.find_by_id(account_id)

        if not account:
            raise AccountNotFoundException(account_id)

        account.agree_to_terms()
        return self._repository.save(account)
