class UsagePolicy:

    @staticmethod
    def calculate_token(text: str) -> int:
        # 단순 예시 (실제로는 tokenizer 연동)
        return len(text) // 4
