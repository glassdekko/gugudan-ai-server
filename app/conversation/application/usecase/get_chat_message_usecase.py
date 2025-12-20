from app.conversation.infrastructure.repository.chat_message_repository_impl import ChatMessageRepositoryImpl
from app.config.security.message_crypto import AESEncryption


class GetChatMessagesUseCase:
    def __init__(self, chat_message_repo: ChatMessageRepositoryImpl, crypto_service: AESEncryption):
        self.chat_message_repo = chat_message_repo
        self.crypto_service = crypto_service

    async def execute(self, room_id: str):
        """
        채팅방의 메시지를 조회하고 복호화하여 반환합니다.
        """
        # 1. DB에서 해당 방의 모든 메시지 조회
        messages = await self.chat_message_repo.find_by_room_id(room_id)
        decrypted = []

        for m in messages:
            content_text = ""

            # ORM 객체(m)에서 직접 컬럼에 접근 (getattr를 활용해 안전하게 추출)
            # m.content_enc, m.iv, m.message_id 등의 필드명을 가정합니다.
            content_enc = getattr(m, 'content_enc', None)
            iv = getattr(m, 'iv', None)

            # 2. 메시지 복호화 로직
            if not content_enc:
                content_text = ""
            else:
                try:
                    target_iv = iv if (iv and len(iv) == 16) else None
                    content_text = self.crypto_service.decrypt(
                        ciphertext=content_enc,
                        iv=target_iv
                    )
                except Exception as e:
                    msg_id = getattr(m, 'message_id', getattr(m, 'id', 'unknown'))
                    print(f"복호화 에러 (ID: {msg_id}): {e}")
                    content_text = "[복호화 오류]"

            # 3. 반환 데이터 조립
            decrypted.append({
                "message_id": getattr(m, 'message_id', getattr(m, 'id', None)),
                "room_id": m.room_id,
                "account_id": m.account_id,
                "role": m.role.value if hasattr(m.role, 'value') else str(m.role),
                "content": content_text,
                "contents_type": getattr(m, 'contents_type', getattr(m, 'content_type', 'TEXT')),
                "created_at": m.created_at,
            })

        return decrypted