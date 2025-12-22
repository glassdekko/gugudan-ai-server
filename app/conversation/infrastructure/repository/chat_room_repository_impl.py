from app.config.database.session import get_db_session
from app.conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort
from app.conversation.infrastructure.orm.chat_room_orm import ChatRoomOrm
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

    async def delete_by_room_id(self, room_id: str) -> bool:
        try:
            # 1. 방 조회
            room = self.db.query(ChatRoomOrm).filter(ChatRoomOrm.room_id == room_id).first()

            if not room:
                return False

            # 2. 방 삭제 (이때 연관된 메시지들이 CASCADE 설정에 의해 자동 삭제됨)
            self.db.delete(room)
            self.db.commit()
            return True

        except Exception as e:
            self.db.rollback()
            raise e