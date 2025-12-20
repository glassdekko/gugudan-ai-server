class ConversationService:
    """
    대화에 대한 순수 도메인 규칙
    """
    @staticmethod
    def can_user_send_message(message_count: int, max_allowed: int) -> bool:
        return message_count < max_allowed