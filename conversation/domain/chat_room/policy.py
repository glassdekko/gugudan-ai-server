class ChatRoomPolicy:
    """
    채팅방 생성/유지 관련 순수 규칙
    """
    @staticmethod
    def can_create_room(current_room_count: int, max_allowed: int) -> bool:
        return current_room_count < max_allowed