from datetime import datetime

from .enums import MessageRole, ContentType
from .value_object import EncryptedContent


class ChatMessage:
    """
    chat_msg 테이블에 1:1 대응
    """

    def __init__(
        self,
        message_id: int | None,
        room_id: str,
        account_id: int,
        role: MessageRole,
        content: EncryptedContent,
        content_type: ContentType,
        created_at: datetime,
        updated_at: datetime | None = None,
        img_url: str | None = None,
    ):
        self.message_id = message_id
        self.room_id = room_id
        self.account_id = account_id
        self.role = role

        self.content = content
        self.content_type = content_type
        self.img_url = img_url

        self.created_at = created_at
        self.updated_at = updated_at
