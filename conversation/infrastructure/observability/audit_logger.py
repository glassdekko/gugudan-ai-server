import logging


class AuditLogger:
    """보안 / 감사 로그"""

    def __init__(self):
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

    def log_chat_event(self, account_id: int, room_id: str, action: str):
        self.logger.info(
            f"[CHAT] user={account_id} room={room_id} action={action}"
        )
