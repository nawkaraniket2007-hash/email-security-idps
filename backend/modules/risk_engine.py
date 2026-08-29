"""
MailSentinel - Risk Engine
==========================

Combines findings from the individual email security analyzers
and produces one normalized risk assessment.

Important:
    This module does NOT inspect the email directly.
    It consumes analyzer results.

Risk levels:
    0-19   SAFE
    20-49  LOW_RISK
    50-74  SUSPICIOUS
    75-100 PHISHING

The score is capped at 100.

The engine also produces explainable findings so the SOC dashboard
can show WHY an email received its final classification.
"""

from __future__ import annotations

import argparse
import json
from typing import Any


# ============================================================
# Configuration
# ============================================================

ENGINE_NAME = "MailSentinel Risk Engine"
ENGINE_VERSION = "1.0"

MAX_SCORE = 100


# ============================================================
# Severity weights
# ============================================================

SEVERITY_WEIGHTS = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 4,
    "info": 0,
}


# ============================================================
# Classification
# ============================================================

def classify_score(score: int) -> str:
    """
    Convert a numerical risk score into a classification.
    """

    score = max(0, min(score, MAX_SCORE))

    if score >= 75:
        return "phishing"

    if score >= 50:
        return "suspicious"

    if score >= 20:
        return "low_risk"

    return "safe"


# ============================================================
# Severity normalization
# ============================================================

def _normalize_severity(
    severity: Any,
) -> str:
    """
    Normalize severity values.
    """

    if not severity:
        return "info"

    value = str(
        severity
    ).strip().lower()

    if value not in SEVERITY_WEIGHTS:
        return "info"

    return value


# ============================================================
# Finding extraction
# ============================================================

def _extract_findings(
    analyzer_name: str,
    analyzer_result: Any,
) -> list[dict[str, Any]]:
    """
    Extract findings from an analyzer result.

    Supports analyzer output containing:
        findings: [...]

    Also supports URL analyzer style output:
        urls: [
            {
                findings: [...]
            }
        ]
    """

    findings: list[dict[str, Any]] = []

    if not isinstance(
        analyzer_result,
        dict,
    ):
        return findings

    # --------------------------------------------------------
    # Top-level findings
    # --------------------------------------------------------

    top_level = analyzer_result.get(
        "findings",
        [],
    )

    if isinstance(
        top_level,
        list,
    ):

        for finding in top_level:

            if not isinstance(
                finding,
                dict,
            ):
                continue

            normalized = dict(
                finding
            )

            normalized[
                "analyzer"
            ] = analyzer_name

            findings.append(
                normalized
            )

    # --------------------------------------------------------
    # Nested URL findings
    # --------------------------------------------------------

    urls = analyzer_result.get(
        "urls",
        [],
    )

    if isinstance(
        urls,
        list,
    ):

        for index, url_result in enumerate(
            urls
        ):

            if not isinstance(
                url_result,
                dict,
            ):
                continue

            nested_findings = (
                url_result.get(
                    "findings",
                    [],
                )
            )

            if not isinstance(
                nested_findings,
                list,
            ):
                continue

            for finding in nested_findings:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                normalized = dict(
                    finding
                )

                normalized[
                    "analyzer"
                ] = analyzer_name

                normalized[
                    "url_index"
                ] = index

                normalized[
                    "url"
                ] = url_result.get(
                    "url"
                )

                findings.append(
                    normalized
                )

    return findings


# ============================================================
# Analyzer score extraction
# ============================================================

def _get_analyzer_score(
    analyzer_result: Any,
) -> int:
    """
    Read an analyzer's own score.

    This value is used as supporting evidence,
    not blindly added to the final score.
    """

    if not isinstance(
        analyzer_result,
        dict,
    ):
        return 0

    score = analyzer_result.get(
        "score",
        0,
    )

    try:
        score = int(score)
    except (
        TypeError,
        ValueError,
    ):
        return 0

    return max(0, score)


# ============================================================
# Finding score calculation
# ============================================================

def _calculate_finding_score(
    finding: dict[str, Any],
) -> int:
    """
    Calculate contribution from one finding.

    If the analyzer already supplied a numeric score,
    use it.

    Otherwise use severity.
    """

    score = finding.get(
        "score"
    )

    if score is not None:

        try:
            return max(
                0,
                int(score),
            )

        except (
            TypeError,
            ValueError,
        ):
            pass

    severity = _normalize_severity(
        finding.get(
            "severity"
        )
    )

    return SEVERITY_WEIGHTS[
        severity
    ]

def _security_override(
    findings: list[dict[str, Any]],
) -> str | None:
    """
    Detect high-confidence malicious combinations that
    should override the numerical score classification.
    """

    indicators = {
        str(finding.get("indicator", "")).lower()
        for finding in findings
    }

    # High-confidence malicious attachment pattern.
    if (
        "executable_attachment" in indicators
        and "double_extension" in indicators
    ):
        return "phishing"

    return None

# ============================================================
# Duplicate finding protection
# ============================================================

def _deduplicate_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Prevent the same indicator from being counted
    repeatedly.
    """

    unique: list[dict[str, Any]] = []

    seen: set[
        tuple[Any, ...]
    ] = set()

    for finding in findings:

        key = (
            finding.get(
                "analyzer"
            ),
            finding.get(
                "indicator"
            ),
            finding.get(
                "url"
            ),
            finding.get(
                "description"
            ),
        )

        if key in seen:
            continue

        seen.add(key)

        unique.append(
            finding
        )

    return unique


# ============================================================
# Correlation bonuses
# ============================================================

def _calculate_correlation_bonus(
    analyzer_results: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    """
    Detect combinations of independent signals.

    Correlation is important because a single weak indicator
    should not normally produce a phishing verdict.

    Examples:
        Reply-To mismatch + suspicious URL
        Credential language + password form
        Header anomaly + suspicious URL
    """

    bonus = 0
    findings: list[dict[str, Any]] = []

    header = analyzer_results.get(
        "header_analyzer",
        {},
    )

    url = analyzer_results.get(
        "url_analyzer",
        {},
    )

    html = analyzer_results.get(
        "html_analyzer",
        {},
    )

    # --------------------------------------------------------
    # Header anomalies
    # --------------------------------------------------------

    header_anomalies = {}

    if isinstance(
        header,
        dict,
    ):

        header_anomalies = (
            header.get(
                "anomalies",
                {},
            )
        )

    reply_to_mismatch = bool(
        isinstance(
            header_anomalies,
            dict,
        )
        and header_anomalies.get(
            "reply_to_domain_mismatch",
            False,
        )
    )

    # --------------------------------------------------------
    # URL risk
    # --------------------------------------------------------

    suspicious_url = False
    high_risk_url = False

    if isinstance(
        url,
        dict,
    ):

        statistics = url.get(
            "statistics",
            {},
        )

        if isinstance(
            statistics,
            dict,
        ):

            suspicious_url = (
                statistics.get(
                    "suspicious_urls",
                    0,
                )
                > 0
            )

            high_risk_url = (
                statistics.get(
                    "high_risk_urls",
                    0,
                )
                > 0
            )

    # --------------------------------------------------------
    # HTML credential harvesting
    # --------------------------------------------------------

    credential_form = False

    if isinstance(
        html,
        dict,
    ):

        statistics = html.get(
            "statistics",
            {},
        )

        if isinstance(
            statistics,
            dict,
        ):

            password_inputs = (
                statistics.get(
                    "password_input_count",
                    0,
                )
            )

            forms = (
                statistics.get(
                    "form_count",
                    0,
                )
            )

            credential_form = (
                forms > 0
                and password_inputs > 0
            )

    # --------------------------------------------------------
    # Correlation: header + suspicious URL
    # --------------------------------------------------------

    if (
        reply_to_mismatch
        and suspicious_url
    ):

        bonus += 12

        findings.append(
            {
                "indicator": (
                    "header_url_correlation"
                ),
                "severity": "high",
                "score": 12,
                "description": (
                    "A Reply-To domain mismatch "
                    "is combined with a suspicious URL."
                ),
            }
        )

    # --------------------------------------------------------
    # Correlation: header + high-risk URL
    # --------------------------------------------------------

    if (
        reply_to_mismatch
        and high_risk_url
    ):

        bonus += 18

        findings.append(
            {
                "indicator": (
                    "header_high_risk_url_correlation"
                ),
                "severity": "critical",
                "score": 18,
                "description": (
                    "A sender identity anomaly "
                    "is combined with a high-risk URL."
                ),
            }
        )

    # --------------------------------------------------------
    # Credential harvesting form
    # --------------------------------------------------------

    if credential_form:

        bonus += 20

        findings.append(
            {
                "indicator": (
                    "credential_harvesting_form"
                ),
                "severity": "high",
                "score": 20,
                "description": (
                    "The HTML contains a form "
                    "with a password input, which "
                    "may indicate credential harvesting."
                ),
            }
        )

    return (
        bonus,
        findings,
    )


# ============================================================
# Main risk assessment
# ============================================================

def analyze_risk(
    analyzer_results: dict[str, Any],
) -> dict[str, Any]:
    """
    Combine analyzer results into a final risk assessment.

    Expected input:

        {
            "header_analyzer": {...},
            "url_analyzer": {...},
            "html_analyzer": {...},
            "attachment_analyzer": {...},
            "ai_analyzer": {...}
        }

    Missing analyzers are allowed.
    """

    if not isinstance(
        analyzer_results,
        dict,
    ):

        raise TypeError(
            "analyzer_results must be a dictionary"
        )

    # --------------------------------------------------------
    # Collect findings
    # --------------------------------------------------------

    all_findings: list[
        dict[str, Any]
    ] = []

    analyzer_scores: dict[
        str,
        int,
    ] = {}

    analyzer_status: dict[
        str,
        str,
    ] = {}

    for analyzer_name, result in (
        analyzer_results.items()
    ):

        analyzer_scores[
            analyzer_name
        ] = _get_analyzer_score(
            result
        )

        if isinstance(
            result,
            dict,
        ):

            analyzer_status[
                analyzer_name
            ] = str(
                result.get(
                    "status",
                    "unknown",
                )
            )

        findings = _extract_findings(
            analyzer_name,
            result,
        )

        all_findings.extend(
            findings
        )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    all_findings = (
        _deduplicate_findings(
            all_findings
        )
    )

    # --------------------------------------------------------
    # Calculate finding score
    # --------------------------------------------------------

    finding_score = 0

    for finding in all_findings:

        finding_score += (
            _calculate_finding_score(
                finding
            )
        )

    # --------------------------------------------------------
    # Correlation score
    # --------------------------------------------------------

    correlation_score, correlation_findings = (
        _calculate_correlation_bonus(
            analyzer_results
        )
    )

    all_findings.extend(
        correlation_findings
    )

    # --------------------------------------------------------
    # Calculate final score
    # --------------------------------------------------------

    raw_score = (
        finding_score
        + correlation_score
    )

    final_score = min(
        raw_score,
        MAX_SCORE,
    )
    
    # Normal score-based classification.
        
    classification = classify_score(
        final_score
    )

    # Apply high-confidence security overrides.
    security_override = _security_override(
        all_findings
    )

    if security_override is not None:
        classification = security_override

    # --------------------------------------------------------
    # Severity statistics
    # --------------------------------------------------------

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in all_findings:

        severity = (
            _normalize_severity(
                finding.get(
                    "severity"
                )
            )
        )

        severity_counts[
            severity
        ] += 1

    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    independent_sources = 0

    for analyzer_name, score in (
        analyzer_scores.items()
    ):

        if score > 0:

            independent_sources += 1

    if independent_sources >= 3:

        confidence = "high"

    elif independent_sources == 2:

        confidence = "medium"

    elif independent_sources == 1:

        confidence = "low"

    else:

        confidence = "very_low"

    # --------------------------------------------------------
    # Human-readable explanation
    # --------------------------------------------------------

    explanations: list[str] = []

    for finding in all_findings:

        description = finding.get(
            "description"
        )

        if description:

            explanations.append(
                str(description)
            )

    # Remove duplicate explanations.
    explanations = list(
        dict.fromkeys(
            explanations
        )
    )

    # --------------------------------------------------------
    # Recommended action
    # --------------------------------------------------------

    if classification == "phishing":

        recommended_action = (
            "quarantine"
        )

    elif classification == "suspicious":

        recommended_action = (
            "review"
        )

    elif classification == "low_risk":

        recommended_action = (
            "allow_with_warning"
        )

    else:

        recommended_action = (
            "allow"
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION,
        },

        "score": final_score,

        "classification": classification,

        "security_override": (
             security_override is not None
        ),

        "confidence": confidence,

        "recommended_action": (
            recommended_action
        ),

        "score_breakdown": {
            "finding_score": finding_score,
            "correlation_score": (
                correlation_score
            ),
            "raw_score": raw_score,
            "final_score": final_score,
        },

        "analyzer_scores": analyzer_scores,

        "analyzer_status": analyzer_status,

        "statistics": {
            "finding_count": len(
                all_findings
            ),
            "critical": severity_counts[
                "critical"
            ],
            "high": severity_counts[
                "high"
            ],
            "medium": severity_counts[
                "medium"
            ],
            "low": severity_counts[
                "low"
            ],
            "info": severity_counts[
                "info"
            ],
            "independent_analyzers": (
                independent_sources
            ),
        },

        "findings": all_findings,

        "explanations": explanations,

        "status": classification,
    }


# ============================================================
# Load analyzer results from JSON
# ============================================================

def load_json_file(
    file_path: str,
) -> dict[str, Any]:
    """
    Load analyzer results from a JSON file.
    """

    with open(
        file_path,
        "r",
        encoding="utf-8",
    ) as file:

        data = json.load(
            file
        )

    if not isinstance(
        data,
        dict,
    ):

        raise ValueError(
            "JSON root must be an object"
        )

    return data


# ============================================================
# CLI
# ============================================================

def main() -> None:
    """
    Command-line interface.

    Usage:

        python3 -m backend.modules.risk_engine results.json
    """

    parser = argparse.ArgumentParser(
        description=(
            "MailSentinel Risk Engine"
        )
    )

    parser.add_argument(
        "results",
        help=(
            "JSON file containing analyzer results"
        ),
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help=(
            "Pretty-print JSON output"
        ),
    )

    args = parser.parse_args()

    try:

        analyzer_results = (
            load_json_file(
                args.results
            )
        )

        result = analyze_risk(
            analyzer_results
        )

        if args.pretty:

            print(
                json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False,
                )
            )

        else:

            print(
                json.dumps(
                    result,
                    ensure_ascii=False,
                )
            )

    except Exception as exc:

        print(
            json.dumps(
                {
                    "error": str(exc),
                },
                indent=2,
            )
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
