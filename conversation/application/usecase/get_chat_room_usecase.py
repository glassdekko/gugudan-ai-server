from conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort


class GetChatRoomsUseCase:

    def __init__(self, chat_room_repo: ChatRoomRepositoryPort):
        self.chat_room_repo = chat_room_repo

    async def execute(self, account_id: int):
        return await self.chat_room_repo.find_by_account_id(account_id)