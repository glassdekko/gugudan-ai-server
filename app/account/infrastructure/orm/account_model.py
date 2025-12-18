"""SQLAlchemy ORM model for Account."""

from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from config.database.session import Base


class AccountModel(Base):
    """SQLAlchemy model for the account table.

    Maps to the domain Account entity for persistence.
    """

    __tablename__ = "account"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    nickname = Column(String(100), nullable=False)
    terms_agreed = Column(Boolean, default=False, nullable=False)
    terms_agreed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime, server_default=func.now(), onupdate=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<AccountModel(id={self.id}, email={self.email})>"
