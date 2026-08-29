"""
MailSentinel - URL Analyzer

Static analysis of URLs extracted from emails.

Security principles:
- Never visit URLs during analysis.
- Never execute JavaScript.
- Never download remote content.
- Produce evidence for the central Risk Engine.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import unquote, urlparse


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
}

SUSPICIOUS_PORTS = {
    21,
    22,
    23,
    25,
    110,
    143,
    445,
    3389,
    5900,
    8080,
    8443,
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "credential",
    "secure",
    "security",
    "update",
    "confirm",
    "authentication",
    "wallet",
    "payment",
    "invoice",
    "bank",
    "crypto",
}


def _clean_url(url: str) -> str:
    """Remove punctuation accidentally attached to URLs."""

    return url.strip().rstrip(
        ".,;:!?)]}\"'"
    )


def _extract_domain(parsed_url: Any) -> str:
    """Safely extract hostname from parsed URL."""

    try:
        return (parsed_url.hostname or "").lower()
    except (ValueError, AttributeError):
        return ""


def _is_ip_address(hostname: str) -> bool:
    """Check whether hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_punycode(hostname: str) -> bool:
    """Detect IDN/Punycode hostname labels."""

    return any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )


def _is_shortener(hostname: str) -> bool:
    """Check against known URL-shortening services."""

    return hostname.strip(".").lower() in SHORTENER_DOMAINS


def _count_subdomains(hostname: str) -> int:
    """Approximate number of subdomain labels."""

    if not hostname:
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def _contains_suspicious_keywords(url: str) -> list[str]:
    """Find security-related keywords in the URL."""

    decoded = unquote(url).lower()

    return sorted(
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in decoded
    )


def _detect_obfuscation(url: str) -> list[str]:
    """Detect common URL-obfuscation indicators."""

    indicators: list[str] = []

    decoded = unquote(url)

    if "%" in url:
        indicators.append("percent_encoding")

    if "\\" in url:
        indicators.append("backslash_character")

    if "@" in url:
        indicators.append("at_symbol")

    if "0x" in decoded.lower():
        indicators.append("hexadecimal_indicator")

    return indicators


def _add_finding(
    findings: list[dict[str, Any]],
    indicator: str,
    severity: str,
    score: int,
    description: str,
) -> None:
    """Add a standardized finding."""

    findings.append(
        {
            "indicator": indicator,
            "severity": severity,
            "score": score,
            "description": description,
        }
    )


def analyze_single_url(url: str) -> dict[str, Any]:
    """
    Analyze one URL without making any network request.
    """

    url = _clean_url(url)

    findings: list[dict[str, Any]] = []

    try:
        parsed = urlparse(url)
    except ValueError as exc:
        return {
            "url": url,
            "valid": False,
            "error": str(exc),
            "findings": [],
            "score": 0,
            "status": "invalid",
        }

    scheme = parsed.scheme.lower()
    hostname = _extract_domain(parsed)

    # ---------------------------------------------------------
    # Basic validation
    # ---------------------------------------------------------

    if scheme not in {"http", "https"}:
        _add_finding(
            findings,
            "unsupported_scheme",
            "medium",
            5,
            f"Unexpected URL scheme: {scheme or 'none'}.",
        )

    if not hostname:
        _add_finding(
            findings,
            "missing_hostname",
            "high",
            8,
            "The URL does not contain a valid hostname.",
        )

    # ---------------------------------------------------------
    # HTTP
    # ---------------------------------------------------------

    if scheme == "http":
        _add_finding(
            findings,
            "unencrypted_http",
            "low",
            3,
            (
                "The URL uses HTTP instead of HTTPS. "
                "HTTP alone does not prove malicious intent."
            ),
        )

    # ---------------------------------------------------------
    # IP address
    # ---------------------------------------------------------

    is_ip = _is_ip_address(hostname)

    if is_ip:
        _add_finding(
            findings,
            "ip_address_url",
            "high",
            10,
            (
                "The URL uses an IP address instead of a "
                "conventional domain."
            ),
        )

    # ---------------------------------------------------------
    # Punycode
    # ---------------------------------------------------------

    punycode = _is_punycode(hostname)

    if punycode:
        _add_finding(
            findings,
            "punycode_domain",
            "medium",
            6,
            (
                "The hostname contains a Punycode/IDN label. "
                "This may indicate a look-alike domain."
            ),
        )

    # ---------------------------------------------------------
    # URL shortener
    # ---------------------------------------------------------

    shortened = _is_shortener(hostname)

    if shortened:
        _add_finding(
            findings,
            "url_shortener",
            "medium",
            5,
            (
                "The URL uses a known shortening service, "
                "which hides the final destination."
            ),
        )

    # ---------------------------------------------------------
    # Port
    # ---------------------------------------------------------

    try:
        port = parsed.port
    except ValueError:
        port = None

        _add_finding(
            findings,
            "invalid_port",
            "medium",
            5,
            "The URL contains an invalid port definition.",
        )

    if port in SUSPICIOUS_PORTS:
        _add_finding(
            findings,
            "suspicious_port",
            "medium",
            5,
            f"The URL uses port {port}.",
        )

    # ---------------------------------------------------------
    # Subdomains
    # ---------------------------------------------------------

    subdomain_count = _count_subdomains(hostname)

    if subdomain_count >= 4:
        _add_finding(
            findings,
            "excessive_subdomains",
            "medium",
            5,
            (
                "The hostname contains an unusually large "
                "number of subdomain labels."
            ),
        )

    # ---------------------------------------------------------
    # URL length
    # ---------------------------------------------------------

    if len(url) > 200:
        _add_finding(
            findings,
            "very_long_url",
            "low",
            3,
            "The URL is unusually long.",
        )

    # ---------------------------------------------------------
    # Obfuscation
    # ---------------------------------------------------------

    obfuscation_indicators = _detect_obfuscation(url)

    if obfuscation_indicators:
        _add_finding(
            findings,
            "url_obfuscation",
            "medium",
            5,
            (
                "The URL contains encoding or character "
                "patterns that may indicate obfuscation."
            ),
        )

    # ---------------------------------------------------------
    # User information / @ symbol
    # ---------------------------------------------------------

    if parsed.username or parsed.password:
        _add_finding(
            findings,
            "userinfo_in_url",
            "high",
            8,
            (
                "The URL contains user information before "
                "the hostname."
            ),
        )

    # ---------------------------------------------------------
    # Security-related keywords
    # ---------------------------------------------------------

    suspicious_keywords = _contains_suspicious_keywords(url)

    if suspicious_keywords:
        _add_finding(
            findings,
            "security_sensitive_keywords",
            "low",
            2,
            (
                "Security-sensitive keywords found: "
                + ", ".join(suspicious_keywords)
            ),
        )

    # ---------------------------------------------------------
    # URL characteristics
    # ---------------------------------------------------------

    has_query = bool(parsed.query)
    has_fragment = bool(parsed.fragment)

    # ---------------------------------------------------------
    # Score
    # ---------------------------------------------------------

    raw_score = sum(
        finding["score"]
        for finding in findings
    )

    score = min(raw_score, 30)

    high_count = sum(
        1
        for finding in findings
        if finding["severity"] == "high"
    )

    medium_count = sum(
        1
        for finding in findings
        if finding["severity"] == "medium"
    )

    low_count = sum(
        1
        for finding in findings
        if finding["severity"] == "low"
    )

    if high_count > 0:
        status = "high_risk"
    elif medium_count > 0:
        status = "suspicious"
    elif low_count > 0:
        status = "low_risk"
    else:
        status = "normal"

    return {
        "url": url,
        "valid": bool(hostname),

        "scheme": scheme,
        "hostname": hostname,
        "port": port,

        "characteristics": {
            "is_ip_address": is_ip,
            "is_punycode": punycode,
            "is_shortened": shortened,
            "subdomain_count": subdomain_count,
            "has_query": has_query,
            "has_fragment": has_fragment,
            "length": len(url),
            "obfuscation_indicators": obfuscation_indicators,
            "security_keywords": suspicious_keywords,
        },

        "findings": findings,

        "score": score,
        "status": status,
    }


def analyze_urls(
    parsed_email: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze all URLs extracted by the email parser.
    """

    url_data = parsed_email.get("urls", {})

    urls = url_data.get("items", [])

    if not isinstance(urls, list):
        urls = []

    results: list[dict[str, Any]] = []

    for url in urls:

        if not isinstance(url, str):
            continue

        try:
            result = analyze_single_url(url)
            results.append(result)

        except Exception as exc:
            results.append(
                {
                    "url": url,
                    "valid": False,
                    "error": str(exc),
                    "findings": [],
                    "score": 0,
                    "status": "error",
                }
            )

    total_score = sum(
        result.get("score", 0)
        for result in results
    )

    analyzer_score = min(total_score, 30)

    high_risk_urls = sum(
        1
        for result in results
        if result.get("status") == "high_risk"
    )

    suspicious_urls = sum(
        1
        for result in results
        if result.get("status") == "suspicious"
    )

    low_risk_urls = sum(
        1
        for result in results
        if result.get("status") == "low_risk"
    )

    if high_risk_urls > 0:
        status = "high_risk"
    elif suspicious_urls > 0:
        status = "suspicious"
    elif low_risk_urls > 0:
        status = "low_risk"
    elif results:
        status = "normal"
    else:
        status = "no_urls"

    return {
        "analyzer": "url_analyzer",
        "version": "1.0",

        "statistics": {
            "url_count": len(results),
            "high_risk_urls": high_risk_urls,
            "suspicious_urls": suspicious_urls,
            "low_risk_urls": low_risk_urls,
        },

        "urls": results,

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
            "backend.modules.url_analyzer <email.eml>"
        )
        sys.exit(1)

    try:

        parsed_email = parse_email(sys.argv[1])

        result = analyze_urls(parsed_email)

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
