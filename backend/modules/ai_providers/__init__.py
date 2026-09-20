"""
Provider-independent AI backends for MailSentinel.

Providers generate text from a shared prompt. The orchestrator in
ai_analyzer.py normalizes responses and owns fallback policy.
"""

from __future__ import annotations

from backend.modules.ai_providers.base import (
    AIProvider,
    ProviderError,
    ProviderResult,
)
from backend.modules.ai_providers.gemini import GeminiProvider
from backend.modules.ai_providers.groq import GroqProvider


PROVIDERS: dict[str, type[AIProvider]] = {
    "gemini": GeminiProvider,
    "groq": GroqProvider,
}


def get_provider(name: str) -> AIProvider:
    """
    Instantiate a configured provider by name.
    """

    key = (name or "").strip().lower()

    if key not in PROVIDERS:
        raise ProviderError(
            provider=key or "unknown",
            message=f"Unsupported AI provider: {name!r}",
            retryable=False,
        )

    return PROVIDERS[key]()


__all__ = [
    "AIProvider",
    "ProviderError",
    "ProviderResult",
    "GeminiProvider",
    "GroqProvider",
    "PROVIDERS",
    "get_provider",
]
