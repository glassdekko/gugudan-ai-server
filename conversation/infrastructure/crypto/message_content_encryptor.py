from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from dataclasses import dataclass


@dataclass
class EncryptedPayload:
    ciphertext: bytes
    iv: bytes
    version: int = 1


class MessageContentEncryptor:
    """채팅 메시지 암호화 전용"""

    def __init__(self, secret_key: bytes):
        self.secret_key = secret_key

    def encrypt(self, plain_text: str) -> EncryptedPayload:
        iv = get_random_bytes(16)
        cipher = AES.new(self.secret_key, AES.MODE_CFB, iv=iv)
        encrypted = cipher.encrypt(plain_text.encode("utf-8"))
        return EncryptedPayload(ciphertext=encrypted, iv=iv)

    def decrypt(self, payload: EncryptedPayload) -> str:
        cipher = AES.new(self.secret_key, AES.MODE_CFB, iv=payload.iv)
        decrypted = cipher.decrypt(payload.ciphertext)
        return decrypted.decode("utf-8")
