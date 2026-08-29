"""
MailSentinel - Header Analyzer

Analyzes email headers for security-relevant anomalies.

IMPORTANT:
This module does NOT decide whether an email is phishing.
It produces evidence and risk indicators for the Risk Engine.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse


def _extract_domain(address: str | None) -> str | None:
    """Extract the domain from an email address."""

    if not address:
        return None

    _, email_address = parseaddr(address)

    if "@" not in email_address:
        return None

    domain = email_address.rsplit("@", 1)[1].strip().lower()

    return domain or None


def _get_header(
    headers: dict[str, Any],
    name: str,
) -> Any:
    """Case-insensitive header lookup."""

    target = name.lower()

    for key, value in headers.items():
        if key.lower() == target:
            return value

    return None


def _normalize_authentication_result(
    value: Any,
) -> str:
    """Convert authentication header data to a searchable string."""

    if value is None:
        return ""

    if isinstance(value, list):
        return " ".join(str(item) for item in value).lower()

    return str(value).lower()


def _extract_auth_result(
    authentication_header: str,
    mechanism: str,
) -> str:
    """
    Extract SPF/DKIM/DMARC result from Authentication-Results.

    Example:

        spf=pass
        dkim=fail
        dmarc=none
    """

    pattern = rf"\b{re.escape(mechanism)}\s*=\s*([a-zA-Z]+)"

    match = re.search(
        pattern,
        authentication_header,
        flags=re.IGNORECASE,
    )

    if not match:
        return "unknown"

    return match.group(1).lower()


def _add_finding(
    findings: list[dict[str, Any]],
    indicator: str,
    severity: str,
    score: int,
    description: str,
) -> None:
    """Add a standardized security finding."""

    findings.append(
        {
            "indicator": indicator,
            "severity": severity,
            "score": score,
            "description": description,
        }
    )


def analyze_headers(
    parsed_email: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze parsed email headers.

    Returns:
        A normalized header-analysis result containing:
        - sender information
        - authentication status
        - anomalies
        - findings
        - analyzer score
    """

    metadata = parsed_email.get("metadata", {})
    headers = parsed_email.get("headers", {})

    findings: list[dict[str, Any]] = []

    # ---------------------------------------------------------
    # Basic sender information
    # ---------------------------------------------------------

    from_header = metadata.get("from", "")
    reply_to = metadata.get("reply_to", "")

    return_path = _get_header(
        headers,
        "Return-Path",
    )

    message_id = metadata.get("message_id", "")

    from_domain = _extract_domain(from_header)
    reply_to_domain = _extract_domain(reply_to)
    return_path_domain = _extract_domain(return_path)

    # ---------------------------------------------------------
    # From / Reply-To mismatch
    # ---------------------------------------------------------

    reply_to_mismatch = False

    if from_domain and reply_to_domain:

        if from_domain != reply_to_domain:

            reply_to_mismatch = True

            _add_finding(
                findings=findings,
                indicator="reply_to_domain_mismatch",
                severity="medium",
                score=8,
                description=(
                    "The Reply-To domain differs from the From domain. "
                    "This can be legitimate, but it is also commonly "
                    "observed in phishing and impersonation attempts."
                ),
            )

    # ---------------------------------------------------------
    # From / Return-Path mismatch
    # ---------------------------------------------------------

    return_path_mismatch = False

    if from_domain and return_path_domain:

        if from_domain != return_path_domain:

            return_path_mismatch = True

            _add_finding(
                findings=findings,
                indicator="return_path_domain_mismatch",
                severity="low",
                score=4,
                description=(
                    "The Return-Path domain differs from the From domain. "
                    "This can occur because of legitimate mail infrastructure."
                ),
            )

    # ---------------------------------------------------------
    # Authentication-Results
    # ---------------------------------------------------------

    authentication_results = _get_header(
        headers,
        "Authentication-Results",
    )

    auth_string = _normalize_authentication_result(
        authentication_results
    )

    spf_result = _extract_auth_result(
        auth_string,
        "spf",
    )

    dkim_result = _extract_auth_result(
        auth_string,
        "dkim",
    )

    dmarc_result = _extract_auth_result(
        auth_string,
        "dmarc",
    )

    # ---------------------------------------------------------
    # SPF
    # ---------------------------------------------------------

    if spf_result == "fail":

        _add_finding(
            findings,
            "spf_fail",
            "high",
            10,
            "SPF authentication failed.",
        )

    elif spf_result == "softfail":

        _add_finding(
            findings,
            "spf_softfail",
            "medium",
            6,
            "SPF authentication returned softfail.",
        )

    # ---------------------------------------------------------
    # DKIM
    # ---------------------------------------------------------

    if dkim_result == "fail":

        _add_finding(
            findings,
            "dkim_fail",
            "high",
            10,
            "DKIM authentication failed.",
        )

    # ---------------------------------------------------------
    # DMARC
    # ---------------------------------------------------------

    if dmarc_result == "fail":

        _add_finding(
            findings,
            "dmarc_fail",
            "high",
            12,
            "DMARC authentication failed.",
        )

    # ---------------------------------------------------------
    # Missing authentication information
    # ---------------------------------------------------------

    if not authentication_results:

        _add_finding(
            findings,
            "missing_authentication_results",
            "info",
            2,
            (
                "No Authentication-Results header was found. "
                "This is not proof of malicious activity because "
                "the email may have been generated outside a normal "
                "mail delivery environment."
            ),
        )

    # ---------------------------------------------------------
    # Message-ID
    # ---------------------------------------------------------

    message_id_present = bool(message_id)

    if not message_id_present:

        _add_finding(
            findings,
            "missing_message_id",
            "low",
            2,
            (
                "The email does not contain a Message-ID header. "
                "Some legitimate systems may omit or alter this header."
            ),
        )

    # ---------------------------------------------------------
    # Received headers
    # ---------------------------------------------------------

    received_headers = _get_header(
        headers,
        "Received",
    )

    if received_headers is None:

        received_count = 0

    elif isinstance(received_headers, list):

        received_count = len(received_headers)

    else:

        received_count = 1

    # ---------------------------------------------------------
    # Suspicious domain characteristics
    # ---------------------------------------------------------

    suspicious_domain_indicators: list[str] = []

    if from_domain:

        try:

            parsed_domain = urlparse(
                f"https://{from_domain}"
            )

            hostname = parsed_domain.hostname or ""

            # IP address used as sender domain.
            if re.fullmatch(
                r"\d{1,3}(\.\d{1,3}){3}",
                hostname,
            ):

                suspicious_domain_indicators.append(
                    "ip_address_sender_domain"
                )

                _add_finding(
                    findings,
                    "ip_address_sender_domain",
                    "high",
                    10,
                    (
                        "The sender domain appears to be an IPv4 "
                        "address rather than a conventional domain."
                    ),
                )

            # Punycode / IDN indicator.
            if "xn--" in hostname:

                suspicious_domain_indicators.append(
                    "punycode_sender_domain"
                )

                _add_finding(
                    findings,
                    "punycode_sender_domain",
                    "medium",
                    6,
                    (
                        "The sender domain contains a Punycode label. "
                        "This is not inherently malicious but warrants "
                        "additional inspection for look-alike domains."
                    ),
                )

        except Exception:
            pass

    # ---------------------------------------------------------
    # Calculate analyzer score
    # ---------------------------------------------------------

    raw_score = sum(
        finding["score"]
        for finding in findings
    )

    # Prevent a single analyzer from exceeding its maximum.
    analyzer_score = min(raw_score, 25)

    # ---------------------------------------------------------
    # Determine analyzer-level status
    # ---------------------------------------------------------

    high_findings = sum(
        1
        for finding in findings
        if finding["severity"] == "high"
    )

    medium_findings = sum(
        1
        for finding in findings
        if finding["severity"] == "medium"
    )

    if high_findings > 0:

        status = "high_risk"

    elif medium_findings > 0:

        status = "suspicious"

    else:

        status = "normal"

    return {
        "analyzer": "header_analyzer",
        "version": "1.0",

        "sender": {
            "from": from_header,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "reply_to_domain": reply_to_domain,
            "return_path": return_path,
            "return_path_domain": return_path_domain,
        },

        "authentication": {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "authentication_results_present": bool(
                authentication_results
            ),
        },

        "structure": {
            "message_id_present": message_id_present,
            "received_header_count": received_count,
        },

        "anomalies": {
            "reply_to_domain_mismatch": reply_to_mismatch,
            "return_path_domain_mismatch": return_path_mismatch,
            "suspicious_domain_indicators": (
                suspicious_domain_indicators
            ),
        },

        "findings": findings,

        "statistics": {
            "finding_count": len(findings),
            "high": high_findings,
            "medium": medium_findings,
        },

        "score": analyzer_score,

        "status": status,
    }


if __name__ == "__main__":

    import json
    import sys

    from .email_parser import parse_email

    if len(sys.argv) != 2:

        print(
            "Usage: python3 -m "
            "backend.modules.header_analyzer <email.eml>"
        )

        sys.exit(1)

    try:

        parsed = parse_email(sys.argv[1])

        result = analyze_headers(parsed)

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )

    except Exception as exc:

        print(f"ERROR: {exc}")

        sys.exit(1)
