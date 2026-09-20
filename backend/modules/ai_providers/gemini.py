"""
Google Gemini AI provider for MailSentinel.
"""

from __future__ import annotations

import os
from typing import Any

from backend.modules.ai_providers.base import (
    AIProvider,
    ProviderError,
    ProviderResult,
)


DEFAULT_GEMINI_MODEL = "gemini-3.6-flash"


def _safe_error_message(exc: Exception) -> str:
    """
    Build a log-safe error message without API key material.
    """

    text = str(exc) or exc.__class__.__name__
    lowered = text.lower()

    for marker in ("key=", "api_key", "authorization", "bearer "):
        if marker in lowered:
            return f"{exc.__class__.__name__}: redacted provider error"

    # Keep messages short to avoid leaking request payloads.
    if len(text) > 240:
        text = text[:237] + "..."

    return text


class GeminiProvider(AIProvider):
    """
    Primary MailSentinel AI provider (Google Gemini).
    """

    name = "gemini"

    def __init__(self) -> None:
        self.api_key = (os.getenv("GEMINI_API_KEY") or "").strip()
        self.model = (
            os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL
        ).strip()

    def generate(self, prompt: str) -> ProviderResult:
        if not self.api_key:
            raise ProviderError(
                provider=self.name,
                message="GEMINI_API_KEY is not configured.",
                retryable=False,
            )

        try:
            from google import genai
            from google.genai import errors as genai_errors
        except Exception as exc:
            raise ProviderError(
                provider=self.name,
                message=f"Gemini SDK unavailable: {exc.__class__.__name__}",
                retryable=False,
            ) from exc

        try:
            client = genai.Client(api_key=self.api_key)
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
            )
        except Exception as exc:
            raise self._to_provider_error(exc, genai_errors) from exc

        text = getattr(response, "text", None)

        if not text or not str(text).strip():
            raise ProviderError(
                provider=self.name,
                message="Gemini returned an empty response.",
                retryable=True,
            )

        raw: dict[str, Any] | None = None

        try:
            raw = {
                "model_version": getattr(response, "model_version", None),
            }
        except Exception:
            raw = None

        return ProviderResult(
            provider=self.name,
            model=self.model,
            text=str(text).strip(),
            raw=raw,
        )

    def _to_provider_error(
        self,
        exc: Exception,
        genai_errors: Any,
    ) -> ProviderError:
        status_code: int | None = getattr(exc, "code", None)

        if isinstance(status_code, int) is False:
            status_code = None

        retryable = False

        api_error = getattr(genai_errors, "APIError", ())
        server_error = getattr(genai_errors, "ServerError", ())
        client_error = getattr(genai_errors, "ClientError", ())

        if isinstance(exc, server_error):
            retryable = True
        elif isinstance(exc, client_error) and status_code in {
            408,
            429,
        }:
            retryable = True
        elif isinstance(exc, api_error) and status_code in {
            408,
            429,
            500,
            502,
            503,
            504,
        }:
            retryable = True
        else:
            # Network / transient transport failures.
            name = exc.__class__.__name__.lower()
            message = str(exc).lower()

            if any(
                token in name or token in message
                for token in (
                    "timeout",
                    "timed out",
                    "connection",
                    "temporarily",
                    "unavailable",
                    "rate limit",
                    "resource_exhausted",
                    "429",
                )
            ):
                retryable = True

        return ProviderError(
            provider=self.name,
            message=_safe_error_message(exc),
            retryable=retryable,
            status_code=status_code,
        )
