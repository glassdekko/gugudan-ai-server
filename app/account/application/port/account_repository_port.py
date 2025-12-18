"""Account repository port - Interface for account persistence."""

from abc import ABC, abstractmethod
from typing import Optional

from app.account.domain.entity.account import Account


class AccountRepositoryPort(ABC):
    """Port (interface) for account repository.

    This defines the contract that any account persistence adapter must implement.
    Following hexagonal architecture, the application layer defines this port,
    and the infrastructure layer provides the implementation.
    """

    @abstractmethod
    def find_by_id(self, account_id: int) -> Optional[Account]:
        """Find an account by its ID.

        Args:
            account_id: The account's unique identifier.

        Returns:
            The Account if found, None otherwise.
        """
        pass

    @abstractmethod
    def find_by_email(self, email: str) -> Optional[Account]:
        """Find an account by email address.

        Args:
            email: The email address to search for.

        Returns:
            The Account if found, None otherwise.
        """
        pass

    @abstractmethod
    def save(self, account: Account) -> Account:
        """Save an account (create or update).

        Args:
            account: The account to save.

        Returns:
            The saved account with updated fields (e.g., ID for new accounts).
        """
        pass

    @abstractmethod
    def exists_by_email(self, email: str) -> bool:
        """Check if an account exists with the given email.

        Args:
            email: The email address to check.

        Returns:
            True if an account exists, False otherwise.
        """
        pass
