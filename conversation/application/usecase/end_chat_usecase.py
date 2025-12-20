from conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort


class EndChatUsecase:

    def __init__(
        self,
        chat_room_repo: ChatRoomRepositoryPort,
    ):
        self.chat_room_repo = chat_room_repo

    async def execute(
        self,
        room_id: str,
        account_id: int,
    ) -> None:
        await self.chat_room_repo.end_room(room_id)
