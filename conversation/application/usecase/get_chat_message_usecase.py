from conversation.application.port.out.chat_message_repository_port import ChatMessageRepositoryPort


class GetChatMessagesUseCase:

    def __init__(self, chat_message_repo: ChatMessageRepositoryPort):
        self.chat_message_repo = chat_message_repo

    async def execute(self, room_id: str):
        return await self.chat_message_repo.find_by_room_id(room_id)
