from typing import AsyncIterator, List
from conversation.application.port.out.chat_message_repository_port import ChatMessageRepositoryPort
from conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort
from conversation.application.port.out.llm_chat_port import LlmChatPort
from conversation.application.port.out.usage_meter_port import UsageMeterPort


class StreamChatUsecase:

    def __init__(
        self,
        chat_room_repo: ChatRoomRepositoryPort,
        chat_message_repo: ChatMessageRepositoryPort,
        llm_chat_port: LlmChatPort,
        usage_meter: UsageMeterPort,
    ):
        self.chat_room_repo = chat_room_repo
        self.chat_message_repo = chat_message_repo
        self.llm_chat_port = llm_chat_port
        self.usage_meter = usage_meter

    async def execute(
        self,
        room_id: str,
        account_id: int,
        message: str,
        contents_type: str,
    ) -> AsyncIterator[bytes]:

        # 1️⃣ 사용 가능 여부 체크
        await self.usage_meter.check_available(account_id)

        # 2️⃣ USER 메시지 저장
        await self.chat_message_repo.save_user_message(
            room_id=room_id,
            account_id=account_id,
            content_enc=message.encode(),
            iv=b"dummy_iv",
            enc_version=1,
            contents_type=contents_type,
        )

        # 3️⃣ LLM 요청
        messages = [{"role": "user", "content": message}]

        assistant_full_message = ""

        async for chunk in self.llm_chat_port.stream_chat(messages):
            assistant_full_message += chunk
            yield chunk.encode("utf-8")

        # 4️⃣ ASSISTANT 메시지 저장 (stream 종료 후)
        await self.chat_message_repo.save_assistant_message(
            room_id=room_id,
            account_id=account_id,
            content_enc=assistant_full_message.encode(),
            iv=b"dummy_iv",
            enc_version=1,
            contents_type=contents_type,
        )

        # 5️⃣ 사용량 기록
        await self.usage_meter.record_usage(
            account_id,
            len(message),
            len(assistant_full_message),
        )
