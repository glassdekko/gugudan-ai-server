from enum import Enum

class MessageRole(Enum):
    USER = "USER"
    ASSISTANT = "ASSISTANT"


class ContentType(Enum):
    TEXT = "TEXT"
    IMAGE = "IMAGE"
    FILE = "FILE"
    SYSTEM = "SYSTEM"