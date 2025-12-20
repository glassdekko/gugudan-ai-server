from abc import ABC, abstractmethod
from typing import AsyncIterator


class ChatUsecasePort(ABC):

    @abstractmethod
    async def start_chat(
        self,
        account_id: int,
        title: str | None,
        category: str,
        division: str,
        out_api: str,
    ) -> str:
        """채팅방 생성 → room_id 반환"""
        pass

    @abstractmethod
    async def stream_chat(
        self,
        room_id: str,
        account_id: int,
        message: str,
        contents_type: str,
    ) -> AsyncIterator[str]:
        """LLM 응답 스트리밍"""
        pass

    @abstractmethod
    async def end_chat(
        self,
        room_id: str,
        account_id: int,
    ) -> None:
        """채팅 종료"""
        pass
