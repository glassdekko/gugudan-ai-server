from conversation.domain.chat_message.entity import ChatMessage
from conversation.domain.chat_room.entity import ChatRoom


class Conversation:
    """
    Aggregate Root
    ChatRoom 1 : N ChatMessage
    """

    def __init__(self, room: ChatRoom, messages: list[ChatMessage]):
        self.room = room
        self.messages = messages

    def append_message(self, message: ChatMessage) -> None:
        if self.room.status != "ACTIVE":
            raise Exception("채팅방이 활성 상태가 아닙니다.")
        self.messages.append(message)