from fastapi import APIRouter, Depends, Body, HTTPException
import uuid
from app.auth.adapter.input.web.dependencies import get_optional_jwt_payload, get_optional_session
from app.auth.application.port.jwt_token_port import TokenPayload
from app.auth.domain.entity.session import Session

from app.conversation.infrastructure.repository.chat_room_repository_impl import ChatRoomRepositoryImpl
from app.conversation.infrastructure.repository.chat_message_repository_impl import ChatMessageRepositoryImpl
from app.config.call_gpt import CallGPT
from app.conversation.infrastructure.repository.usage_meter_impl import UsageMeterImpl
from app.conversation.application.usecase.stream_chat_usecase import StreamChatUsecase
from app.conversation.application.usecase.get_chat_message_usecase import GetChatMessagesUseCase
from app.conversation.application.usecase.get_chat_room_usecase import GetChatRoomsUseCase
from app.conversation.adapter.output.stream.stream_adapter import StreamAdapter
from app.config.security.message_crypto import AESEncryption

crypto_service = AESEncryption()

# =============================
# 2. DI 객체 구성
# =============================
chat_room_repo = ChatRoomRepositoryImpl()
chat_message_repo = ChatMessageRepositoryImpl()
llm_chat_port = CallGPT()
usage_meter = UsageMeterImpl()

stream_chat_usecase = StreamChatUsecase(
    chat_room_repo=chat_room_repo,
    chat_message_repo=chat_message_repo,
    llm_chat_port=llm_chat_port,
    usage_meter=usage_meter,
    crypto_service=crypto_service
)

conversation_router = APIRouter(tags=["conversation"])


# =============================
# 인증 로직 (기존 유지)
# =============================
def get_current_account_id(
        jwt_payload: TokenPayload | None = Depends(get_optional_jwt_payload),
        session: Session | None = Depends(get_optional_session),
) -> int:
    if jwt_payload:
        return jwt_payload.account_id
    if session:
        return session.account_id
    raise HTTPException(status_code=401, detail="Not authenticated")


# =============================
# GET 내 채팅방 목록
# =============================
@conversation_router.get("/rooms")
async def get_my_rooms(account_id: int = Depends(get_current_account_id)):
    uc = GetChatRoomsUseCase(chat_room_repo)
    return await uc.execute(account_id)


# =============================
# GET 특정 채팅방 메시지 (복호화 포함)
# =============================
@conversation_router.get("/rooms/{room_id}/messages")
async def get_room_messages(room_id: str, account_id: int = Depends(get_current_account_id)):
    uc = GetChatMessagesUseCase(chat_message_repo, crypto_service)
    return await uc.execute(room_id)


# =============================
# POST AI 스트리밍 채팅 (GPT-4.1 스트리밍)
# =============================
@conversation_router.post("/chat/stream-auto")
async def stream_chat_auto(
        account_id: int = Depends(get_current_account_id),
        message: str = Body(..., embed=True),
        room_id: str | None = Body(default=None, embed=True),
):
    # 신규 방 생성 로직
    if room_id is None:
        room_id = str(uuid.uuid4())
        await chat_room_repo.create(
            room_id=room_id,
            account_id=account_id,
            title=message[:20],
            category="GENERAL",
            division="DEFAULT",
            out_api=False
        )
    else:
        room = await chat_room_repo.find_by_id(room_id)
        if not room:
            raise HTTPException(status_code=404, detail="Room not found")

    # 스트리밍 실행 (제너레이터 반환)
    generator = stream_chat_usecase.execute(
        room_id=room_id,
        account_id=account_id,
        message=message,
        contents_type="TEXT",
    )

    # SSE(Server-Sent Events) 등으로 클라이언트에 한 글자씩 전달
    return StreamAdapter.to_streaming_response(generator)