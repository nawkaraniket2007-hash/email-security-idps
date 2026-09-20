"""
Groq AI provider for MailSentinel (OpenAI-compatible HTTP API).

Uses httpx, which is already required by google-genai / the project.
No additional SDK dependency is introduced.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from backend.modules.ai_providers.base import (
    AIProvider,
    ProviderError,
    ProviderResult,
)


DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_CHAT_URL = "https://api.groq.com/openai/v1/chat/completions"


def _safe_error_message(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    lowered = text.lower()

    for marker in ("key=", "api_key", "authorization", "bearer "):
        if marker in lowered:
            return f"{exc.__class__.__name__}: redacted provider error"

    if len(text) > 240:
        text = text[:237] + "..."

    return text


class GroqProvider(AIProvider):
    """
    Fallback MailSentinel AI provider (Groq).
    """

    name = "groq"

    def __init__(self) -> None:
        self.api_key = (os.getenv("GROQ_API_KEY") or "").strip()
        self.model = (
            os.getenv("GROQ_MODEL") or DEFAULT_GROQ_MODEL
        ).strip()
        self.timeout = float(os.getenv("GROQ_TIMEOUT_SECONDS") or "60")

    def generate(self, prompt: str) -> ProviderResult:
        if not self.api_key:
            raise ProviderError(
                provider=self.name,
                message="GROQ_API_KEY is not configured.",
                retryable=False,
            )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a cybersecurity email analysis assistant. "
                        "Return ONLY valid JSON. Do not wrap the JSON in "
                        "Markdown fences."
                    ),
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
            "response_format": {"type": "json_object"},
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(
                    GROQ_CHAT_URL,
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ProviderError(
                provider=self.name,
                message="Groq request timed out.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise ProviderError(
                provider=self.name,
                message=_safe_error_message(exc),
                retryable=True,
            ) from exc

        if response.status_code >= 400:
            raise ProviderError(
                provider=self.name,
                message=self._http_error_message(response),
                retryable=response.status_code
                in {408, 429, 500, 502, 503, 504},
                status_code=response.status_code,
            )

        try:
            body = response.json()
        except Exception as exc:
            raise ProviderError(
                provider=self.name,
                message="Groq returned invalid JSON.",
                retryable=True,
                status_code=response.status_code,
            ) from exc

        text = self._extract_text(body)

        if not text:
            raise ProviderError(
                provider=self.name,
                message="Groq returned an empty response.",
                retryable=True,
                status_code=response.status_code,
            )

        return ProviderResult(
            provider=self.name,
            model=self.model,
            text=text,
            raw={
                "id": body.get("id"),
                "model": body.get("model"),
            },
        )

    def _extract_text(self, body: dict[str, Any]) -> str:
        choices = body.get("choices")

        if not isinstance(choices, list) or not choices:
            return ""

        message = choices[0].get("message") if isinstance(choices[0], dict) else None

        if not isinstance(message, dict):
            return ""

        content = message.get("content")

        if isinstance(content, str):
            return content.strip()

        return ""

    def _http_error_message(self, response: httpx.Response) -> str:
        status = response.status_code

        try:
            payload = response.json()
            error = payload.get("error") if isinstance(payload, dict) else None

            if isinstance(error, dict):
                message = str(error.get("message") or "").strip()
                error_type = str(error.get("type") or "").strip()

                if message and "key" not in message.lower():
                    detail = f"{error_type}: {message}" if error_type else message
                    return f"Groq HTTP {status}: {detail[:180]}"
        except Exception:
            pass

        return f"Groq HTTP {status}"
