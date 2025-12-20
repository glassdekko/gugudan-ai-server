from fastapi import APIRouter, Depends, Cookie, Body
from starlette import status

from app.auth.adapter.input.web.dependencies import get_auth_usecase
from app.auth.application.usecase.auth_usecase import AuthUseCase
from conversation.adapter.output.stream.stream_adapter import StreamAdapter
from conversation.application.usecase.get_chat_message_usecase import GetChatMessagesUseCase
from conversation.application.usecase.get_chat_room_usecase import GetChatRoomsUseCase

from conversation.infrastructure.repository.chat_room_repository_impl import (
    ChatRoomRepositoryImpl,
)
from conversation.infrastructure.repository.chat_message_repository_impl import (
    ChatMessageRepositoryImpl,
)
from conversation.adapter.output.llm.openai_adapter import OpenAiAdapter
from conversation.infrastructure.repository.usage_meter_impl import UsageMeterImpl

from conversation.application.usecase.stream_chat_usecase import StreamChatUsecase


def get_current_account_id(
    session_id: str | None = Cookie(default=None),
    auth_usecase: AuthUseCase = Depends(get_auth_usecase),
) -> int:
    if not session_id:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found",
        )

    session = auth_usecase.validate_session(session_id)
    if not session:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session",
        )

    return session.account_id

# =============================
# Application 조립 (DI 수동)
# =============================

chat_room_repo = ChatRoomRepositoryImpl()
chat_message_repo = ChatMessageRepositoryImpl()
llm_chat_port = OpenAiAdapter()
usage_meter = UsageMeterImpl()

stream_chat_usecase = StreamChatUsecase(
    chat_room_repo=chat_room_repo,
    chat_message_repo=chat_message_repo,
    llm_chat_port=llm_chat_port,
    usage_meter=usage_meter,
)

# =============================
# Router
# =============================

conversation_router = APIRouter(tags=["conversation"])


@conversation_router.post("/chat/stream")
async def stream_chat():
    generator = stream_chat_usecase.execute(
        room_id="room-id",
        account_id=1,
        message="hello",
        contents_type="TEXT",
    )
    return StreamAdapter.to_streaming_response(generator)

@conversation_router.post("/chat/test")
async def test_chat():
    result = stream_chat_usecase.execute(
        room_id="test-room-1",
        account_id=1,
        message="안녕",
        contents_type="TEXT",
    )

    first_chunk = None
    async for chunk in result:
        first_chunk = chunk
        break

    return {
        "result": first_chunk
    }

@conversation_router.get("/rooms")
async def get_my_rooms(
    account_id: int = Depends(get_current_account_id),
):
    uc = GetChatRoomsUseCase(ChatRoomRepositoryImpl())
    return await uc.execute(account_id)


@conversation_router.get("/rooms/{room_id}/messages")
async def get_room_messages(room_id: str):
    uc = GetChatMessagesUseCase(ChatMessageRepositoryImpl())
    return await uc.execute(room_id)

@conversation_router.post("/chat/stream-auto")
async def stream_chat_auto(
    account_id: int = Depends(get_current_account_id),
    message: str = Body(...),
    room_id: str | None = Body(default=None),
):
    """
    room_id가 없으면 메시지 입력 시 자동으로 새 채팅방 생성
    """
    # ============================
    # 1. 새 채팅방 생성
    # ============================
    if room_id is None:
        room = chat_room_repo.create(
            room_id=None,              # DB에서 자동 생성
            account_id=account_id,
            title=message[:20],        # 메시지 앞 20자로 방 제목
            category="GENERAL",        # 기본 카테고리
            division="DEFAULT",        # 기본 division
            out_api=False              # 외부 API 여부
        )
        # 리턴 타입이 dict/객체에 따라 접근 방식 조정
        room_id = getattr(room, "room_id", room.get("room_id"))

    else:
        room = chat_room_repo.rooms.get(room_id)
        if not room:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Room not found")

    # ============================
    # 2. 메시지 스트리밍
    # ============================
    generator = stream_chat_usecase.execute(
        room_id=room_id,
        account_id=account_id,
        message=message,
        contents_type="TEXT",
    )

    return StreamAdapter.to_streaming_response(generator)


