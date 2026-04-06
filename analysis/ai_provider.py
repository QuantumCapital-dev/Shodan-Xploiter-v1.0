"""
AI provider module — Anthropic Claude.

Phase 1 uses Haiku (fast, lightweight identity report).
Phase 2 and 3 use Sonnet (deep reasoning for vulnerability analysis and pentest guide).
"""

import sys
from abc import ABC, abstractmethod

import anthropic
import config

HAIKU_MODEL  = "claude-haiku-4-5-20251001"
SONNET_MODEL = "claude-sonnet-4-6"


class BaseAIProvider(ABC):
    """Minimal interface for AI providers."""

    @abstractmethod
    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        model: str | None = None,
    ) -> str: ...

    def stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        model: str | None = None,
    ):
        """Streaming generator — yields text chunks. Raises NotImplementedError if unsupported."""
        raise NotImplementedError

    @property
    @abstractmethod
    def provider_name(self) -> str: ...

    @property
    @abstractmethod
    def model_name(self) -> str: ...


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude provider with streaming support."""

    def __init__(self) -> None:
        if not config.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY not set in .env — "
                "get your key at https://console.anthropic.com"
            )
        self._client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)

    @property
    def provider_name(self) -> str:
        return "claude"

    @property
    def model_name(self) -> str:
        return SONNET_MODEL

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        model: str | None = None,
    ) -> str:
        message = self._client.messages.create(
            model=model or SONNET_MODEL,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return message.content[0].text

    def stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        model: str | None = None,
    ):
        """Yields raw text chunks for real-time terminal output."""
        with self._client.messages.stream(
            model=model or SONNET_MODEL,
            max_tokens=max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        ) as stream:
            for text in stream.text_stream:
                yield text


def get_provider() -> BaseAIProvider:
    """Returns the active AI provider instance."""
    return AnthropicProvider()
