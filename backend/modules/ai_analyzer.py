from __future__ import annotations

import json
import os
from typing import Any

from dotenv import load_dotenv
from google import genai


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError("GEMINI_API_KEY is not configured.")

client = genai.Client(api_key=API_KEY)


def analyze_with_ai(
    email_data: dict[str, Any],
    analyzer_results: dict[str, Any],
    risk_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate a human-readable security assessment using Gemini.

    Gemini receives the already-computed MailSentinel findings.
    It does not replace the deterministic security analyzers.
    """

    prompt = f"""
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
"""

    try:
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )

        text = response.text.strip()

        # Remove accidental Markdown JSON fencing.
        if text.startswith("```"):
            text = text.replace("```json", "", 1)
            text = text.replace("```", "", 1).strip()

        result = json.loads(text)

        return {
            "analyzer": "ai_analyzer",
            "version": "1.0",
            "status": "completed",
            **result,
        }

    except Exception as exc:
        return {
            "analyzer": "ai_analyzer",
            "version": "1.0",
            "status": "error",
            "summary": "AI analysis could not be completed.",
            "threat_level": "unknown",
            "is_malicious": False,
            "confidence": "low",
            "key_findings": [],
            "recommended_action": "Use the deterministic MailSentinel risk analysis.",
            "user_explanation": "The AI service was unavailable, but the security analyzers completed.",
            "error": str(exc),
        }
