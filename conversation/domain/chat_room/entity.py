from datetime import datetime
from uuid import UUID

from .enums import ChatRoomStatus, ChatCategory, ChatDivision
from .excepetion import ChatRoomAlreadyEnded


class ChatRoom:
    """
    chat_room 테이블에 1:1 대응하는 도메인 엔티티
    """

    def __init__(
        self,
        room_id: UUID,
        account_id: int,
        title: str | None,
        status: ChatRoomStatus,
        category: ChatCategory,
        division: ChatDivision,
        out_api: str,
        created_at: datetime,
        updated_at: datetime,
        started_at: datetime | None = None,
        ended_at: datetime | None = None,
        room_assignment: int | None = None,
    ):
        self.room_id = room_id
        self.account_id = account_id
        self.title = title
        self.status = status
        self.category = category
        self.division = division
        self.out_api = out_api

        self.started_at = started_at
        self.ended_at = ended_at
        self.room_assignment = room_assignment

        self.created_at = created_at
        self.updated_at = updated_at

    def start(self) -> None:
        if self.status == ChatRoomStatus.ENDED:
            raise ChatRoomAlreadyEnded()

        self.status = ChatRoomStatus.ACTIVE
        self.started_at = datetime.utcnow()

    def end(self) -> None:
        if self.status == ChatRoomStatus.ENDED:
            raise ChatRoomAlreadyEnded()

        self.status = ChatRoomStatus.ENDED
        self.ended_at = datetime.utcnow()
