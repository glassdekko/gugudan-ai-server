from sqlalchemy import Column, String, Integer, DateTime
from config.database.session import Base
from datetime import datetime


class ChatRoomOrm(Base):
    __tablename__ = "chat_room"

    room_id = Column(String(36), primary_key=True)
    account_id = Column(Integer, nullable=False)
    title = Column(String(100))
    category = Column(String(20))
    division = Column(String(20))
    out_api = Column(String(50))
    status = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
