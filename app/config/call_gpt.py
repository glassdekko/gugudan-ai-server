"""OpenAI GPT API 호출 모듈."""

import asyncio
import os
from typing import Optional, AsyncIterator

from dotenv import load_dotenv
from openai import AsyncOpenAI
from openai.types.chat import ChatCompletionMessageParam

load_dotenv()

# 환경 변수 검증
MAX_TOKENS_ENV = os.getenv("MAX_TOKENS")
if not MAX_TOKENS_ENV:
    raise ValueError("MAX_TOKENS environment variable is required")

try:
    MAX_TOKENS = int(MAX_TOKENS_ENV)
except ValueError as e:
    raise ValueError(f"MAX_TOKENS must be a valid integer: {e}") from e

# OpenAI 클라이언트 초기화
_async_client: Optional[AsyncOpenAI] = None


def get_async_client() -> AsyncOpenAI:
    """비동기 클라이언트 싱글톤 인스턴스 반환"""
    global _async_client
    if _async_client is None:
        _async_client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return _async_client


async def _create_chat_completion_stream(prompt: str) -> AsyncIterator[str]:
    """비동기 방식으로 GPT API를 호출합니다.
    
    Args:
        prompt: 사용자 프롬프트
        
    Returns:
        GPT 응답 텍스트
        
    Raises:
        ValueError: 프롬프트가 비어있는 경우
        Exception: OpenAI API 호출 실패 시
    """
    if not prompt or not prompt.strip():
        raise ValueError("Prompt cannot be empty")
    
    client = get_async_client()
    
    # 타입 안전성을 위해 딕셔너리를 명시적으로 구성
    message: dict[str, str] = {"role": "user", "content": prompt}
    messages: list[ChatCompletionMessageParam] = [
        message  # type: ignore[list-item]
    ]
    
    try:
        response = await client.chat.completions.create(
            model="gpt-4.1",
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=0,
            stream=True
        )

        async for chunk in response:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    except Exception as e:
        raise Exception(f"Failed to call GPT API: {str(e)}") from e


class CallGPT:
    """OpenAI GPT API를 비동기로 호출하는 클래스."""

    @staticmethod
    async def call_gpt(prompt: str) -> AsyncIterator[str]:
        """비동기 방식으로 GPT API를 호출합니다.
        
        Args:
            prompt: 사용자 프롬프트
            
        Returns:
            GPT 응답 텍스트
            
        Raises:
            ValueError: 프롬프트가 비어있는 경우
            Exception: OpenAI API 호출 실패 시
        """
        try:
            async for chunk in _create_chat_completion_stream(prompt):
                yield chunk
        except Exception as e:
            raise Exception(f"CallGPT 중계 에러: {str(e)}")
