from conversation.application.port.out.chat_message_repository_port import ChatMessageRepositoryPort
from conversation.infrastructure.orm.chat_message_orm import ChatMessageOrm
from config.database.session import get_db_session
from sqlalchemy.orm import Session

class ChatMessageRepositoryImpl(ChatMessageRepositoryPort):

    def __init__(self, session: Session | None = None):
        self.db: Session = session or get_db_session()

    async def save_user_message(self, **kwargs):
        msg = ChatMessageOrm(role="USER", **kwargs)
        self.db.add(msg)
        self.db.commit()

    async def save_assistant_message(self, **kwargs):
        msg = ChatMessageOrm(role="ASSISTANT", **kwargs)
        self.db.add(msg)
        self.db.commit()

    async def find_by_room_id(self, room_id: str):
        return (
            self.db.query(ChatMessageOrm)
            .filter(ChatMessageOrm.room_id == room_id)
            .order_by(ChatMessageOrm.created_at.asc())
            .all()
        )