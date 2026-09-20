"""
Shared AI provider contracts for MailSentinel.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderResult:
    """
    Raw successful response from an AI provider.
    """

    provider: str
    model: str
    text: str
    raw: dict[str, Any] | None = None


class ProviderError(Exception):
    """
    Normalized provider failure.

    retryable=True means the orchestrator may attempt the fallback
    provider (rate limits, timeouts, temporary outages).
    """

    def __init__(
        self,
        provider: str,
        message: str,
        *,
        retryable: bool = False,
        status_code: int | None = None,
    ) -> None:
        self.provider = provider
        self.message = message
        self.retryable = retryable
        self.status_code = status_code
        super().__init__(message)

    def safe_dict(self) -> dict[str, Any]:
        """
        Serialisable error metadata that never includes secrets.
        """

        payload: dict[str, Any] = {
            "provider": self.provider,
            "message": self.message,
            "retryable": self.retryable,
        }

        if self.status_code is not None:
            payload["status_code"] = self.status_code

        return payload


class AIProvider(ABC):
    """
    Interface for provider-specific LLM calls.
    """

    name: str

    @abstractmethod
    def generate(self, prompt: str) -> ProviderResult:
        """
        Call the remote model and return raw text content.
        """
