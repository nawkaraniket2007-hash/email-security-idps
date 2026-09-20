"""
MailSentinel AI Analyzer
========================

Provider-independent AI security assessment layer.

Pipeline position:

    deterministic analyzers
            ↓
        risk engine          ← authoritative for score / classification
            ↓
        AI analyzer          ← explanation / narrative only
            ↓
      primary provider (Gemini by default)
            ↓ (429 / temporary failure)
      fallback provider (Groq by default)
            ↓ (total AI failure)
      deterministic AI fallback result

The AI layer MUST NEVER modify the deterministic risk score.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

from dotenv import load_dotenv

from backend.modules.ai_providers import ProviderError, get_provider


load_dotenv()

logger = logging.getLogger(__name__)

AI_ANALYZER_NAME = "ai_analyzer"
AI_ANALYZER_VERSION = "1.0"

VALID_THREAT_LEVELS = {"low", "medium", "high", "critical"}
VALID_CONFIDENCE = {"low", "medium", "high"}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()

    if not raw:
        return default

    return raw in {"1", "true", "yes", "on"}


def _provider_name(env_name: str, default: str) -> str:
    return (os.getenv(env_name) or default).strip().lower()


def build_prompt(
    email_data: dict[str, Any],
    analyzer_results: dict[str, Any],
    risk_result: dict[str, Any],
) -> str:
    """
    Shared prompt for all AI providers.
    """

    return f"""
You are the AI security analysis component of MailSentinel,
an Email Security Intrusion Detection and Prevention System.

Analyze the following email security telemetry.

EMAIL DATA:
{json.dumps(email_data, indent=2, default=str)}

ANALYZER RESULTS:
{json.dumps(analyzer_results, indent=2, default=str)}

RISK ENGINE:
{json.dumps(risk_result, indent=2, default=str)}

Return ONLY valid JSON using exactly this structure:

{{
  "summary": "Short security assessment.",
  "threat_level": "low|medium|high|critical",
  "is_malicious": true,
  "confidence": "low|medium|high",
  "key_findings": [
    "finding 1",
    "finding 2"
  ],
  "recommended_action": "clear recommendation for the user",
  "user_explanation": "Simple explanation for a non-SOC user."
}}

Rules:
- Base the assessment primarily on the supplied telemetry.
- Do not invent indicators that are not present.
- Do not claim an attachment was executed.
- Treat executable attachments and suspicious double extensions seriously.
- Keep the explanation understandable to a normal email user.
- The deterministic MailSentinel risk score is authoritative for scoring.
- Do not change or contradict the numerical risk score.
"""


def _strip_markdown_fences(text: str) -> str:
    cleaned = text.strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```json", "", 1)
        cleaned = cleaned.replace("```", "", 1).strip()

    return cleaned


def _normalize_threat_level(value: Any) -> str:
    text = str(value or "").strip().lower().replace(" ", "_")

    aliases = {
        "safe": "low",
        "info": "low",
        "informational": "low",
        "low_risk": "low",
        "moderate": "medium",
        "med": "medium",
        "suspicious": "high",
        "severe": "critical",
        "phishing": "critical",
    }

    text = aliases.get(text, text)

    if text in VALID_THREAT_LEVELS:
        return text

    return "medium"


def _normalize_confidence(value: Any) -> str:
    text = str(value or "").strip().lower()

    if text in VALID_CONFIDENCE:
        return text

    return "low"


def _normalize_key_findings(value: Any) -> list[str]:
    if isinstance(value, list):
        findings: list[str] = []

        for item in value:
            text = str(item).strip()

            if text:
                findings.append(text)

        return findings

    if isinstance(value, str) and value.strip():
        return [value.strip()]

    return []


def _parse_model_json(text: str) -> dict[str, Any]:
    cleaned = _strip_markdown_fences(text)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise ProviderError(
            provider="parser",
            message=f"Provider returned invalid JSON: {exc.__class__.__name__}",
            retryable=True,
        ) from exc

    if not isinstance(parsed, dict):
        raise ProviderError(
            provider="parser",
            message="Provider JSON root must be an object.",
            retryable=True,
        )

    return parsed


def _standardized_result(
    *,
    status: str,
    provider: str,
    model: str,
    fallback_used: bool,
    payload: dict[str, Any],
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = {
        "analyzer": AI_ANALYZER_NAME,
        "version": AI_ANALYZER_VERSION,
        "status": status,
        "provider": provider,
        "model": model,
        "fallback_used": bool(fallback_used),
        "summary": str(payload.get("summary") or "").strip()
        or "No AI summary available.",
        "threat_level": _normalize_threat_level(
            payload.get("threat_level")
        ),
        "is_malicious": bool(payload.get("is_malicious")),
        "confidence": _normalize_confidence(
            payload.get("confidence")
        ),
        "key_findings": _normalize_key_findings(
            payload.get("key_findings")
        ),
        "recommended_action": str(
            payload.get("recommended_action") or ""
        ).strip()
        or "Follow the deterministic MailSentinel recommendation.",
        "user_explanation": str(
            payload.get("user_explanation") or ""
        ).strip()
        or "Review the deterministic MailSentinel risk analysis.",
    }

    if extra:
        result.update(extra)

    return result


def _classification_to_threat_level(classification: str) -> str:
    mapping = {
        "safe": "low",
        "low_risk": "low",
        "suspicious": "high",
        "phishing": "critical",
    }

    return mapping.get(classification, "medium")


def build_deterministic_fallback(
    risk_result: dict[str, Any],
    *,
    errors: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Build a usable AI-shaped result from deterministic risk output.

    Used when every configured provider fails. Does not invent
    indicators beyond the risk engine telemetry.
    """

    classification = str(
        risk_result.get("classification") or "unknown"
    ).strip().lower()

    score = risk_result.get("score", 0)
    recommended_action = str(
        risk_result.get("recommended_action") or "review"
    ).replace("_", " ")

    confidence = str(risk_result.get("confidence") or "low").lower()
    threat_level = _classification_to_threat_level(classification)

    is_malicious = classification in {"phishing", "suspicious"}

    findings = risk_result.get("findings") or []
    key_findings: list[str] = []

    if isinstance(findings, list):
        for finding in findings[:5]:
            if not isinstance(finding, dict):
                continue

            indicator = str(finding.get("indicator") or "").strip()
            description = str(finding.get("description") or "").strip()

            if indicator and description:
                key_findings.append(f"{indicator}: {description}")
            elif indicator:
                key_findings.append(indicator)
            elif description:
                key_findings.append(description)

    if not key_findings:
        key_findings = [
            "Deterministic MailSentinel analyzers completed successfully.",
            f"Final classification: {classification or 'unknown'}.",
            f"Risk score: {score}/100.",
        ]

    summary = (
        f"AI providers were unavailable. Deterministic analysis classified "
        f"this email as {classification or 'unknown'} with risk score "
        f"{score}/100."
    )

    user_explanation = (
        "The AI narrative service was temporarily unavailable. "
        "MailSentinel still completed its deterministic security analysis. "
        f"Recommended action: {recommended_action}."
    )

    return _standardized_result(
        status="completed",
        provider="deterministic_fallback",
        model="risk_engine",
        fallback_used=True,
        payload={
            "summary": summary,
            "threat_level": threat_level,
            "is_malicious": is_malicious,
            "confidence": confidence if confidence in VALID_CONFIDENCE else "low",
            "key_findings": key_findings,
            "recommended_action": recommended_action,
            "user_explanation": user_explanation,
        },
        extra={
            "ai_provider_status": "unavailable",
            "provider_errors": errors or [],
        },
    )


def _call_provider(provider_name: str, prompt: str) -> dict[str, Any]:
    provider = get_provider(provider_name)
    provider_result = provider.generate(prompt)
    parsed = _parse_model_json(provider_result.text)

    return _standardized_result(
        status="completed",
        provider=provider_result.provider,
        model=provider_result.model,
        fallback_used=False,
        payload=parsed,
    )


def analyze_with_ai(
    email_data: dict[str, Any],
    analyzer_results: dict[str, Any],
    risk_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a human-readable security assessment via configured providers.

    Never raises. Provider outages return a deterministic fallback result so
    /api/analyze can still succeed.
    """

    primary_name = _provider_name("AI_PRIMARY_PROVIDER", "gemini")
    fallback_name = _provider_name("AI_FALLBACK_PROVIDER", "groq")
    enable_fallback = _env_bool("AI_ENABLE_FALLBACK", True)

    prompt = build_prompt(
        email_data,
        analyzer_results,
        risk_result,
    )

    provider_errors: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # Primary provider
    # --------------------------------------------------------

    try:
        result = _call_provider(primary_name, prompt)
        result["fallback_used"] = False

        logger.info(
            "AI analysis completed via primary provider=%s model=%s",
            result.get("provider"),
            result.get("model"),
        )

        return result

    except ProviderError as exc:
        provider_errors.append(exc.safe_dict())
        logger.warning(
            "Primary AI provider failed provider=%s retryable=%s status=%s error=%s",
            exc.provider,
            exc.retryable,
            exc.status_code,
            exc.message,
        )

        primary_retryable = exc.retryable

    except Exception as exc:
        # Defensive: never let unexpected exceptions escape.
        error = ProviderError(
            provider=primary_name,
            message=f"Unexpected primary provider failure: {exc.__class__.__name__}",
            retryable=True,
        )
        provider_errors.append(error.safe_dict())
        logger.warning(
            "Unexpected primary AI failure provider=%s error=%s",
            primary_name,
            error.message,
        )
        primary_retryable = True

    # --------------------------------------------------------
    # Fallback provider
    # --------------------------------------------------------

    should_try_fallback = (
        enable_fallback
        and fallback_name
        and fallback_name != primary_name
        and primary_retryable
    )

    # Also attempt fallback for non-retryable primary failures when
    # explicitly enabled — temporary outages sometimes surface as
    # generic client errors. Prefer availability of narrative AI.
    if enable_fallback and fallback_name and fallback_name != primary_name:
        should_try_fallback = True

    if should_try_fallback:
        try:
            result = _call_provider(fallback_name, prompt)
            result["fallback_used"] = True

            logger.info(
                "AI analysis completed via fallback provider=%s model=%s",
                result.get("provider"),
                result.get("model"),
            )

            if provider_errors:
                result["provider_errors"] = provider_errors

            return result

        except ProviderError as exc:
            provider_errors.append(exc.safe_dict())
            logger.warning(
                "Fallback AI provider failed provider=%s retryable=%s status=%s error=%s",
                exc.provider,
                exc.retryable,
                exc.status_code,
                exc.message,
            )

        except Exception as exc:
            error = ProviderError(
                provider=fallback_name,
                message=(
                    "Unexpected fallback provider failure: "
                    f"{exc.__class__.__name__}"
                ),
                retryable=False,
            )
            provider_errors.append(error.safe_dict())
            logger.warning(
                "Unexpected fallback AI failure provider=%s error=%s",
                fallback_name,
                error.message,
            )

    # --------------------------------------------------------
    # Deterministic fallback — analysis still succeeds
    # --------------------------------------------------------

    logger.warning(
        "All AI providers unavailable; using deterministic fallback."
    )

    return build_deterministic_fallback(
        risk_result,
        errors=provider_errors,
    )
