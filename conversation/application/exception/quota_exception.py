from conversation.application.exception.application_exception import ApplicationException


class QuotaExceededException(ApplicationException):
    """유저 사용량 초과"""

    def __init__(self, message: str = "Usage quota exceeded"):
        super().__init__(message)
