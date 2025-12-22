from sqlalchemy.orm import Session
from Crypto.Random import get_random_bytes
from app.conversation.infrastructure.orm.chat_message_orm import ChatMessageOrm


class ChatMessageRepositoryImpl:
    def __init__(self, session: Session):
        self.db = session

    async def save_message(self, **kwargs):
        # 1. IV 자동 생성
        try:
            if not kwargs.get('iv'):
                kwargs['iv'] = get_random_bytes(16)

            # 2. parent_id 유효성 검사 (핵심 해결책)
            parent_id = kwargs.get('parent_id')
            if parent_id is not None:
                # 실제로 해당 ID를 가진 메시지가 있는지 DB에서 확인
                exists = self.db.query(ChatMessageOrm).filter(ChatMessageOrm.id == parent_id).first()
                if not exists:
                    # 존재하지 않는다면 외래키 에러를 피하기 위해 None으로 교체
                    print(f"⚠️ Warning: parent_id {parent_id} not found in DB. Setting to None.")
                    kwargs['parent_id'] = None

            # 3. 객체 생성 및 저장
            msg = ChatMessageOrm(**kwargs)
            self.db.add(msg)
            self.db.flush()  # ID 생성을 위해 flush 실행

        except Exception as e:
            self.db.rollback()
            raise e
        finally:
            self.db.close()
        return msg

    async def find_by_room_id(self, room_id: str):
        try:
            return (
                self.db.query(ChatMessageOrm)
                .filter(ChatMessageOrm.room_id == room_id)
                .order_by(ChatMessageOrm.id.asc())
                .all()
            )
        finally:
            self.db.close()