from typing import AsyncIterator
from app.conversation.application.port.out.chat_message_repository_port import ChatMessageRepositoryPort
from app.conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort
from app.config.call_gpt import CallGPT
from app.conversation.application.port.out.usage_meter_port import UsageMeterPort
from app.config.security.message_crypto import AESEncryption


class StreamChatUsecase:
    def __init__(
            self,
            chat_room_repo: ChatRoomRepositoryPort,
            chat_message_repo: ChatMessageRepositoryPort,
            llm_chat_port: CallGPT,
            usage_meter: UsageMeterPort,
            crypto_service: AESEncryption,
    ):
        self.chat_room_repo = chat_room_repo
        self.chat_message_repo = chat_message_repo
        self.llm_chat_port = llm_chat_port
        self.usage_meter = usage_meter
        self.crypto_service = crypto_service

    async def execute(
            self,
            room_id: str,
            account_id: int,
            message: str,
            contents_type: str,
    ) -> AsyncIterator[bytes]:

        await self.usage_meter.check_available(account_id)

        previous_chat_messages = await self.chat_message_repo.find_by_room_id(room_id)

        full_prompt = (
            "당신은 연애, 커플, 이혼 등 관계에서 발생하는 감정과 대화 문제를 함께 나누는 따뜻한 대화 동반자입니다. "
            "사용자를 진단하거나 분석하려 하지 마세요. 사용자가 스스로 생각을 정리할 수 있도록 경청하고 공감하며 대화를 이어가세요.\n\n"
        )

        for m in previous_chat_messages:
            try:
                decrypted_txt = self.crypto_service.decrypt(
                    ciphertext=m.content_enc,
                    iv=m.iv if (m.iv and len(m.iv) == 16) else None
                )
                # 역할을 라벨링하여 문자열로 병합
                role_label = "상담사" if m.role.lower() == "assistant" else "사용자"
                full_prompt += f"{role_label}: {decrypted_txt}\n"
            except Exception as e:
                print(f"이전 메시지 복호화 실패 (ID: {getattr(m, 'id', 'unknown')}): {e}")
                continue

        user_encrypted, user_iv = self.crypto_service.encrypt(message)
        await self.chat_message_repo.save_user_message(
            room_id=room_id,
            account_id=account_id,
            content_enc=user_encrypted,
            iv=user_iv,
            enc_version=self.crypto_service.get_version(),
            contents_type=contents_type,
        )

        full_prompt += f"사용자: {message}\n상담사: "

        assistant_full_message = ""

        async for chunk in self.llm_chat_port.call_gpt(full_prompt):
            assistant_full_message += chunk
            yield chunk.encode("utf-8")

        assistant_encrypted, assistant_iv = self.crypto_service.encrypt(assistant_full_message)
        await self.chat_message_repo.save_assistant_message(
            room_id=room_id,
            account_id=account_id,
            content_enc=assistant_encrypted,
            iv=assistant_iv,
            enc_version=self.crypto_service.get_version(),
            contents_type=contents_type,
        )

        await self.usage_meter.record_usage(
            account_id,
            len(message),
            len(assistant_full_message),
        )