class RolePolicy:

    ROLE_LIMITS = {
        "FREE": {
            "max_rooms": 1,
            "max_message_length": 500,
        },
        "PAID": {
            "max_rooms": 10,
            "max_message_length": 4000,
        },
        "ADMIN": {
            "max_rooms": 999,
            "max_message_length": 10000,
        },
    }

    @classmethod
    def max_message_length(cls, role: str) -> int:
        return cls.ROLE_LIMITS[role]["max_message_length"]
