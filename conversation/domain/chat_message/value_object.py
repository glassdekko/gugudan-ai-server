from dataclasses import dataclass

@dataclass(frozen=True)
class EncryptedContent:
    """
    암호화된 메시지 본문
    """
    content_enc: bytes
    iv: bytes
    enc_version: int
    content_hash: bytes | None = None
