from enum import Enum

class ChatRoomStatus(Enum):
    ACTIVE = "ACTIVE"
    ENDED = "ENDED"

class ChatCategory(Enum):
    LOVE = "LOVE"
    BREAKUP = "BREAKUP"
    DIVORCE = "DIVORCE"
    ETC = "ETC"

class ChatDivision(Enum):
    CONSULT = "CONSULT"
    ANALYSIS = "ANALYSIS"
    FREE = "FREE"