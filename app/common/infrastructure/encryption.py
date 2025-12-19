"""Encryption utilities for secure data handling.

This module provides AES encryption/decryption functionality
for secure storage and transmission of sensitive data.
"""

import base64
import os
import uuid
from typing import Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class AESEncryption:
    """AES encryption/decryption service.

    Uses AES-256-CBC for encryption with PKCS7 padding.
    Each encryption operation generates a unique IV.
    """

    BLOCK_SIZE = 128  # AES block size in bits
    KEY_SIZE = 32  # AES-256 key size in bytes

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure AES-256 key.

        Returns:
            A 32-byte random key.
        """
        return os.urandom(AESEncryption.KEY_SIZE)

    @staticmethod
    def generate_iv() -> bytes:
        """Generate a cryptographically secure initialization vector.

        Returns:
            A 16-byte random IV.
        """
        return os.urandom(16)

    @staticmethod
    def encrypt(plaintext: str, key: bytes) -> Tuple[str, str]:
        """Encrypt plaintext using AES-256-CBC.

        Args:
            plaintext: The text to encrypt.
            key: The AES key (32 bytes for AES-256).

        Returns:
            Tuple of (encrypted_data_base64, iv_base64).
        """
        iv = AESEncryption.generate_iv()

        # Pad the plaintext to block size
        padder = padding.PKCS7(AESEncryption.BLOCK_SIZE).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Return base64 encoded strings
        return base64.b64encode(encrypted).decode('utf-8'), base64.b64encode(iv).decode('utf-8')

    @staticmethod
    def decrypt(encrypted_data_base64: str, iv_base64: str, key: bytes) -> str:
        """Decrypt data encrypted with AES-256-CBC.

        Args:
            encrypted_data_base64: Base64 encoded encrypted data.
            iv_base64: Base64 encoded initialization vector.
            key: The AES key used for encryption.

        Returns:
            The decrypted plaintext.
        """
        encrypted_data = base64.b64decode(encrypted_data_base64)
        iv = base64.b64decode(iv_base64)

        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad
        unpadder = padding.PKCS7(AESEncryption.BLOCK_SIZE).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode('utf-8')


class TokenKeyGenerator:
    """Generator for encrypted user-specific token keys.

    Creates unique, encrypted UUIDs for use as JWT subject identifiers.
    The encryption ensures the key is secure and tied to the user.
    """

    def __init__(self, master_key: bytes):
        """Initialize the key generator.

        Args:
            master_key: The master AES key for encrypting user keys.
        """
        self._master_key = master_key

    def generate_encrypted_user_key(self, user_id: int) -> Tuple[str, str]:
        """Generate an AES-encrypted unique key for a user.

        The key is a UUID combined with the user_id, then encrypted.

        Args:
            user_id: The user's account ID.

        Returns:
            Tuple of (encrypted_key, iv) both base64 encoded.
        """
        # Create a unique identifier combining UUID and user_id
        unique_id = f"{uuid.uuid4().hex}:{user_id}"

        # Encrypt the unique ID
        encrypted_key, iv = AESEncryption.encrypt(unique_id, self._master_key)

        return encrypted_key, iv

    def decrypt_user_key(self, encrypted_key: str, iv: str) -> str:
        """Decrypt a user key.

        Args:
            encrypted_key: Base64 encoded encrypted key.
            iv: Base64 encoded initialization vector.

        Returns:
            The decrypted unique identifier.
        """
        return AESEncryption.decrypt(encrypted_key, iv, self._master_key)

    @staticmethod
    def derive_key_from_secret(secret: str) -> bytes:
        """Derive a 32-byte key from a secret string.

        Uses SHA-256 to ensure consistent key length.

        Args:
            secret: The secret string to derive key from.

        Returns:
            A 32-byte key suitable for AES-256.
        """
        import hashlib
        return hashlib.sha256(secret.encode('utf-8')).digest()
