"""Domain exceptions for the application."""


class DomainException(Exception):
    """Base exception for domain errors."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


# Account exceptions
class AccountNotFoundException(DomainException):
    """Raised when an account is not found."""

    def __init__(self, identifier: str | int):
        super().__init__(f"Account not found: {identifier}")


class AccountAlreadyExistsException(DomainException):
    """Raised when trying to create an account that already exists."""

    def __init__(self, email: str):
        super().__init__(f"Account already exists with email: {email}")


# Auth exceptions
class AuthenticationException(DomainException):
    """Base exception for authentication errors."""

    pass


class InvalidSessionException(AuthenticationException):
    """Raised when session is invalid or expired."""

    def __init__(self):
        super().__init__("Invalid or expired session")


class InvalidCSRFTokenException(AuthenticationException):
    """Raised when CSRF token validation fails."""

    def __init__(self):
        super().__init__("CSRF token validation failed")


class OAuthException(AuthenticationException):
    """Raised when OAuth process fails."""

    def __init__(self, provider: str, message: str):
        super().__init__(f"OAuth error with {provider}: {message}")


class InvalidOAuthStateException(OAuthException):
    """Raised when OAuth state parameter is invalid."""

    def __init__(self, provider: str):
        super().__init__(provider, "Invalid state parameter")


class UnsupportedOAuthProviderException(OAuthException):
    """Raised when an unsupported OAuth provider is requested."""

    def __init__(self, provider: str):
        super().__init__(provider, f"Unsupported OAuth provider: {provider}")
