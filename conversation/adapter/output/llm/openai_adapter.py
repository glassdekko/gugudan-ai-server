from conversation.application.port.out.llm_chat_port import LlmChatPort
from typing import AsyncIterator


class OpenAiAdapter(LlmChatPort):

    async def stream_chat(self, messages) -> AsyncIterator[str]:
        # 실제론 OpenAI streaming API 연결
        for chunk in ["안녕하세요", " 상담을 시작합니다"]:
            yield chunk
