"""
MailSentinel - HTML Analyzer

Static security analysis of HTML email content.

Security principles:
- No JavaScript execution.
- No external HTTP requests.
- No remote resource fetching.
- HTML is treated as untrusted input.
- Produces evidence for the central Risk Engine.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any
from urllib.parse import urlparse

from bs4 import BeautifulSoup


SUSPICIOUS_SCRIPT_PATTERNS = [
    r"\beval\s*\(",
    r"\batob\s*\(",
    r"\bdocument\.write\s*\(",
    r"\bwindow\.location\b",
    r"\blocation\.href\b",
    r"\bfromCharCode\s*\(",
]

CREDENTIAL_KEYWORDS = {
    "password",
    "passwd",
    "credential",
    "username",
    "login",
    "signin",
    "verify",
    "verification",
    "authentication",
    "account",
}

SUSPICIOUS_HTML_ATTRIBUTES = {
    "onclick",
    "onload",
    "onerror",
    "onmouseover",
    "onfocus",
    "onchange",
}


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


def _normalize_url(value: str) -> str:
    """Normalize an extracted URL."""

    if not value:
        return ""

    return value.strip().rstrip(
        ".,;:!?)]}\"'"
    )


def _extract_domain(value: str) -> str:
    """Extract hostname from an HTTP/HTTPS URL."""

    try:
        parsed = urlparse(value)

        if parsed.scheme.lower() not in {"http", "https"}:
            return ""

        return (parsed.hostname or "").lower()

    except (ValueError, AttributeError):
        return ""


def _is_external_url(
    url: str,
    sender_domain: str | None,
) -> bool:
    """
    Determine whether a URL points to a different domain
    than the sender domain.
    """

    if not url:
        return False

    domain = _extract_domain(url)

    if not domain:
        return False

    if not sender_domain:
        return True

    sender_domain = sender_domain.lower().strip(".")

    return not (
        domain == sender_domain
        or domain.endswith("." + sender_domain)
    )


def _get_html(parsed_email: dict[str, Any]) -> str:
    """
    Retrieve HTML content from the parsed email.

    Supports common parser output structures.
    """

    html = parsed_email.get("html")

    if isinstance(html, str):
        return html

    body = parsed_email.get("body", {})

    if isinstance(body, dict):

        html = body.get("html")

        if isinstance(html, str):
            return html

    content = parsed_email.get("content", {})

    if isinstance(content, dict):

        html = content.get("html")

        if isinstance(html, str):
            return html

    return ""


def analyze_html(
    parsed_email: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze HTML content from an email.

    No HTML is rendered and no remote resource is contacted.
    """

    html = _get_html(parsed_email)

    findings: list[dict[str, Any]] = []

    if not html:

        return {
            "analyzer": "html_analyzer",
            "version": "1.0",

            "statistics": {
                "html_present": False,
                "link_count": 0,
                "external_link_count": 0,
                "form_count": 0,
                "script_count": 0,
                "iframe_count": 0,
            },

            "links": [],

            "findings": [],

            "score": 0,

            "status": "no_html",
        }

    # ---------------------------------------------------------
    # Parse HTML
    # ---------------------------------------------------------

    try:

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

    except Exception as exc:

        return {
            "analyzer": "html_analyzer",
            "version": "1.0",

            "statistics": {
                "html_present": True,
            },

            "links": [],

            "findings": [
                {
                    "indicator": "html_parse_error",
                    "severity": "medium",
                    "score": 5,
                    "description": (
                        f"HTML parsing failed: {exc}"
                    ),
                }
            ],

            "score": 5,

            "status": "suspicious",
        }

    # ---------------------------------------------------------
    # Sender domain
    # ---------------------------------------------------------

    metadata = parsed_email.get(
        "metadata",
        {},
    )

    sender = metadata.get(
        "from",
        "",
    )

    sender_domain = ""

    if isinstance(sender, str) and "@" in sender:

        sender_domain = (
            sender.rsplit("@", 1)[-1]
            .strip()
            .lower()
            .rstrip(">")
        )

    # ---------------------------------------------------------
    # Links
    # ---------------------------------------------------------

    links: list[dict[str, Any]] = []

    external_link_count = 0

    link_mismatch_count = 0

    for anchor in soup.find_all("a"):

        href = anchor.get("href")

        if not isinstance(href, str):
            continue

        href = _normalize_url(href)

        if not href:
            continue

        visible_text = anchor.get_text(
            " ",
            strip=True,
        )

        target_domain = _extract_domain(href)

        external = _is_external_url(
            href,
            sender_domain,
        )

        if external:
            external_link_count += 1

        visible_url_domain = _extract_domain(
            visible_text
        )

        mismatch = False

        if visible_url_domain and target_domain:

            if visible_url_domain != target_domain:

                mismatch = True

                link_mismatch_count += 1

                _add_finding(
                    findings,
                    "visible_url_target_mismatch",
                    "high",
                    12,
                    (
                        "The visible URL domain differs from "
                        "the actual hyperlink destination."
                    ),
                )

        links.append(
            {
                "href": href,
                "visible_text": visible_text,
                "target_domain": target_domain,
                "visible_domain": visible_url_domain,
                "external": external,
                "domain_mismatch": mismatch,
            }
        )

    # ---------------------------------------------------------
    # Hidden links
    # ---------------------------------------------------------

    hidden_link_count = 0

    for anchor in soup.find_all("a"):

        style = str(
            anchor.get(
                "style",
                ""
            )
        ).lower()

        if (
            "display:none" in style
            or "display: none" in style
            or "visibility:hidden" in style
            or "visibility: hidden" in style
        ):

            hidden_link_count += 1

    if hidden_link_count > 0:

        _add_finding(
            findings,
            "hidden_links",
            "medium",
            7,
            (
                f"The HTML contains {hidden_link_count} "
                "hidden hyperlink(s)."
            ),
        )

    # ---------------------------------------------------------
    # Forms
    # ---------------------------------------------------------

    forms = soup.find_all("form")

    form_count = len(forms)

    if form_count > 0:

        _add_finding(
            findings,
            "html_form",
            "high",
            10,
            (
                "The email contains an HTML form. "
                "Forms inside emails can be used for "
                "credential harvesting."
            ),
        )

    # ---------------------------------------------------------
    # Password inputs
    # ---------------------------------------------------------

    password_inputs = soup.find_all(
        "input",
        attrs={
            "type": re.compile(
                r"^password$",
                re.IGNORECASE,
            )
        },
    )

    if password_inputs:

        _add_finding(
            findings,
            "password_input",
            "high",
            12,
            (
                "The HTML contains a password input field."
            ),
        )

    # ---------------------------------------------------------
    # Iframes
    # ---------------------------------------------------------

    iframes = soup.find_all("iframe")

    iframe_count = len(iframes)

    if iframe_count > 0:

        _add_finding(
            findings,
            "iframe_present",
            "high",
            10,
            (
                "The email HTML contains an iframe."
            ),
        )

    # ---------------------------------------------------------
    # JavaScript
    # ---------------------------------------------------------

    scripts = soup.find_all("script")

    script_count = len(scripts)

    script_text = " ".join(
        script.get_text(
            " ",
            strip=True,
        )
        for script in scripts
    )

    # Also inspect inline HTML for script-like patterns.
    script_source = (
        script_text
        + " "
        + html
    ).lower()

    script_pattern_matches: list[str] = []

    for pattern in SUSPICIOUS_SCRIPT_PATTERNS:

        if re.search(
            pattern,
            script_source,
            flags=re.IGNORECASE,
        ):

            script_pattern_matches.append(
                pattern
            )

    if script_count > 0:

        _add_finding(
            findings,
            "javascript_present",
            "high",
            12,
            (
                "The email contains JavaScript. "
                "JavaScript inside email HTML is a strong "
                "security concern."
            ),
        )

    if script_pattern_matches:

        _add_finding(
            findings,
            "suspicious_javascript_pattern",
            "high",
            10,
            (
                "Suspicious JavaScript patterns were detected "
                "in the HTML."
            ),
        )

    # ---------------------------------------------------------
    # Event handlers
    # ---------------------------------------------------------

    event_handler_count = 0

    for tag in soup.find_all(True):

        for attribute in tag.attrs:

            attribute_name = str(
                attribute
            ).lower()

            if attribute_name in SUSPICIOUS_HTML_ATTRIBUTES:

                event_handler_count += 1

    if event_handler_count > 0:

        _add_finding(
            findings,
            "javascript_event_handler",
            "high",
            10,
            (
                f"The HTML contains {event_handler_count} "
                "JavaScript event-handler attribute(s)."
            ),
        )

    # ---------------------------------------------------------
    # External resources
    # ---------------------------------------------------------

    external_resource_count = 0

    resource_tags = soup.find_all(
        [
            "img",
            "script",
            "iframe",
            "link",
            "video",
            "audio",
            "source",
        ]
    )

    for tag in resource_tags:

        for attribute in (
            "src",
            "href",
        ):

            value = tag.get(attribute)

            if not isinstance(value, str):
                continue

            value = _normalize_url(value)

            if _extract_domain(value):

                if _is_external_url(
                    value,
                    sender_domain,
                ):

                    external_resource_count += 1

    if external_resource_count >= 5:

        _add_finding(
            findings,
            "many_external_resources",
            "medium",
            5,
            (
                "The email references many external resources."
            ),
        )

    # ---------------------------------------------------------
    # Credential-related text
    # ---------------------------------------------------------

    visible_text = soup.get_text(
        " ",
        strip=True,
    ).lower()

    credential_keywords = sorted(
        keyword
        for keyword in CREDENTIAL_KEYWORDS
        if keyword in visible_text
    )

    if (
        len(credential_keywords) >= 3
        and (form_count > 0 or password_inputs)
    ):

        _add_finding(
            findings,
            "credential_harvesting_indicators",
            "high",
            12,
            (
                "The HTML contains multiple credential-related "
                "keywords together with an input/form element."
            ),
        )

    # ---------------------------------------------------------
    # HTML meta refresh
    # ---------------------------------------------------------

    meta_refresh = False

    for meta in soup.find_all("meta"):

        http_equiv = str(
            meta.get(
                "http-equiv",
                ""
            )
        ).lower()

        if http_equiv == "refresh":

            meta_refresh = True

            _add_finding(
                findings,
                "meta_refresh",
                "medium",
                6,
                (
                    "The HTML contains a meta refresh element."
                ),
            )

    # ---------------------------------------------------------
    # Hidden text
    # ---------------------------------------------------------

    hidden_text_count = 0

    for tag in soup.find_all(True):

        style = str(
            tag.get(
                "style",
                ""
            )
        ).lower()

        if (
            "display:none" in style
            or "display: none" in style
            or "visibility:hidden" in style
            or "visibility: hidden" in style
        ):

            if tag.get_text(
                " ",
                strip=True,
            ):

                hidden_text_count += 1

    if hidden_text_count > 0:

        _add_finding(
            findings,
            "hidden_text",
            "medium",
            5,
            (
                f"The HTML contains {hidden_text_count} "
                "hidden text element(s)."
            ),
        )

    # ---------------------------------------------------------
    # External link concentration
    # ---------------------------------------------------------

    if (
        len(links) > 0
        and external_link_count == len(links)
        and len(links) >= 3
    ):

        _add_finding(
            findings,
            "all_links_external",
            "low",
            3,
            (
                "All detected hyperlinks point to external domains."
            ),
        )

    # ---------------------------------------------------------
    # Score
    # ---------------------------------------------------------

    raw_score = sum(
        finding["score"]
        for finding in findings
    )

    analyzer_score = min(
        raw_score,
        30,
    )

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
        "analyzer": "html_analyzer",
        "version": "1.0",

        "statistics": {
            "html_present": True,
            "link_count": len(links),
            "external_link_count": external_link_count,
            "link_mismatch_count": link_mismatch_count,
            "hidden_link_count": hidden_link_count,
            "form_count": form_count,
            "password_input_count": len(password_inputs),
            "iframe_count": iframe_count,
            "script_count": script_count,
            "event_handler_count": event_handler_count,
            "external_resource_count": (
                external_resource_count
            ),
            "hidden_text_count": hidden_text_count,
            "meta_refresh": meta_refresh,
        },

        "links": links,

        "indicators": {
            "credential_keywords": credential_keywords,
            "javascript_patterns": script_pattern_matches,
        },

        "findings": findings,

        "score": analyzer_score,

        "status": status,
    }


if __name__ == "__main__":

    from .email_parser import parse_email

    if len(sys.argv) != 2:

        print(
            "Usage: python3 -m "
            "backend.modules.html_analyzer <email.eml>"
        )

        sys.exit(1)

    try:

        parsed_email = parse_email(
            sys.argv[1]
        )

        result = analyze_html(
            parsed_email
        )

        print(
            json.dumps(
                result,
                indent=2,
                ensure_ascii=False,
            )
        )

    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        sys.exit(1)
