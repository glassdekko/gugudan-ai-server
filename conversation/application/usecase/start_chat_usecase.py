import uuid
from conversation.application.port.out.chat_room_repository_port import ChatRoomRepositoryPort
from conversation.application.port.out.usage_meter_port import UsageMeterPort


class StartChatUsecase:

    def __init__(
        self,
        chat_room_repo: ChatRoomRepositoryPort,
        usage_meter: UsageMeterPort,
    ):
        self.chat_room_repo = chat_room_repo
        self.usage_meter = usage_meter

    async def execute(
        self,
        account_id: int,
        title: str | None,
        category: str,
        division: str,
        out_api: str,
    ) -> str:
        await self.usage_meter.check_available(account_id)

        room_id = str(uuid.uuid4())

        await self.chat_room_repo.create(
            room_id=room_id,
            account_id=account_id,
            title=title,
            category=category,
            division=division,
            out_api=out_api,
        )

        return room_id
