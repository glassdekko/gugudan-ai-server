from conversation.application.port.out.usage_meter_port import UsageMeterPort


class UsageMeterImpl(UsageMeterPort):

    async def check_available(self, account_id: int) -> None:
        # TODO: Redis / quota 체크
        return None

    async def record_usage(
        self,
        account_id: int,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        total = input_tokens + output_tokens
        # TODO: DB 저장 or 차감
        return None
