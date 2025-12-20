class ChatRoomDomainException(Exception):
    pass


class ChatRoomAlreadyEnded(ChatRoomDomainException):
    pass


class ChatRoomNotActive(ChatRoomDomainException):
    pass
