class ApplicationException(Exception):
    """모든 애플리케이션 예외의 최상위"""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)
