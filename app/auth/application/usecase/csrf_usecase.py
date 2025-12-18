"""CSRF usecase - Token generation and validation."""

import hashlib
import hmac
import secrets

from config.settings import settings


class CSRFUseCase:
    """UseCase for CSRF token management.

    Implements the Double Submit Cookie pattern:
    1. Generate a signed token
    2. Set token in a readable cookie
    3. Client sends token in both cookie and header
    4. Server validates cookie token matches header token
    """

    def __init__(self, secret_key: str | None = None):
        """Initialize CSRF usecase.

        Args:
            secret_key: Secret key for token signing. Uses settings if not provided.
        """
        self._secret = secret_key or settings.CSRF_SECRET_KEY

    def generate_token(self) -> str:
        """Generate a cryptographically secure CSRF token.

        The token consists of random bytes and a HMAC signature.
        Format: {random_hex}.{signature}

        Returns:
            A signed CSRF token string.
        """
        random_bytes = secrets.token_bytes(32)
        signature = hmac.new(
            self._secret.encode(),
            random_bytes,
            hashlib.sha256,
        ).hexdigest()
        return f"{random_bytes.hex()}.{signature}"

    def validate_token(self, cookie_token: str | None, header_token: str | None) -> bool:
        """Validate CSRF tokens using Double Submit Cookie pattern.

        Compares the token from cookie with the token from request header.
        Uses constant-time comparison to prevent timing attacks.

        Args:
            cookie_token: Token from the csrf_token cookie.
            header_token: Token from the X-CSRF-Token header.

        Returns:
            True if tokens match and are valid, False otherwise.
        """
        if not cookie_token or not header_token:
            return False

        # Constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(cookie_token, header_token):
            return False

        # Optionally verify the signature
        return self._verify_signature(cookie_token)

    def _verify_signature(self, token: str) -> bool:
        """Verify the HMAC signature of a token.

        Args:
            token: The token to verify.

        Returns:
            True if signature is valid, False otherwise.
        """
        try:
            parts = token.split(".")
            if len(parts) != 2:
                return False

            random_hex, signature = parts
            random_bytes = bytes.fromhex(random_hex)

            expected_signature = hmac.new(
                self._secret.encode(),
                random_bytes,
                hashlib.sha256,
            ).hexdigest()

            return hmac.compare_digest(signature, expected_signature)
        except (ValueError, TypeError):
            return False
