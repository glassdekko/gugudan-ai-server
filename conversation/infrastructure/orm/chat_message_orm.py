from sqlalchemy import Column, String, Integer, DateTime, LargeBinary
from datetime import datetime
from config.database.session import Base


class ChatMessageOrm(Base):
    __tablename__ = "chat_msg"

    id = Column(Integer, primary_key=True, autoincrement=True)
    room_id = Column(String(36), nullable=False)
    account_id = Column(Integer)
    role = Column(String(20))
    content_enc = Column(LargeBinary, nullable=False)
    iv = Column(LargeBinary, nullable=False)
    enc_version = Column(Integer)
    contents_type = Column(String(20))
    created_at = Column(DateTime, default=datetime.utcnow)
