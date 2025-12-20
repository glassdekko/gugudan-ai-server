from config.database.session import get_db_session
from conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort
from conversation.infrastructure.orm.chat_room_orm import ChatRoomOrm
from sqlalchemy.orm import Session

class ChatRoomRepositoryImpl(ChatRoomRepositoryPort):

    def __init__(self, session: Session | None = None):
        self.db: Session = session or get_db_session()

    async def create(self, room_id, account_id, title, category, division, out_api):
        room = ChatRoomOrm(
            room_id=room_id,
            account_id=account_id,
            title=title,
            category=category,
            division=division,
            out_api=out_api,
            status="ACTIVE",
        )
        self.db.add(room)
        self.db.commit()

    async def find_by_id(self, room_id):
        return self.db.get(ChatRoomOrm, room_id)

    async def end_room(self, room_id):
        room = await self.db.get(ChatRoomOrm, room_id)
        room.status = "ENDED"
        self.db.commit()

    async def find_by_account_id(self, account_id: int):
        return (
            self.db.query(ChatRoomOrm)
            .filter(ChatRoomOrm.account_id == account_id)
            .order_by(ChatRoomOrm.created_at.desc())
            .all()
        )