"""
MailSentinel - Email Parser
===========================

Purpose:
    Safely parse .eml files and normalize their contents for
    downstream cybersecurity analyzers.

Responsibilities:
    - Parse RFC-compliant .eml files
    - Extract email headers
    - Extract sender / recipient information
    - Extract plain-text and HTML bodies
    - Extract and normalize URLs
    - Extract attachment metadata
    - Calculate SHA-256 hashes for attachments
    - Detect MIME structure
    - Preserve useful evidence for downstream analyzers

Security principles:
    - Never execute attachments
    - Never open attachments as programs
    - Never visit URLs
    - Never make network requests
    - Treat all email content as untrusted input
    - Do not make final phishing/malware decisions here

The parser only extracts and normalizes evidence.
"""

from __future__ import annotations

import hashlib
import mimetypes
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any


# ============================================================
# Constants
# ============================================================

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)

MARKDOWN_URL_PATTERN = re.compile(
    r"\]\(\s*(https?://[^)\s<>\"']+)\s*\)",
    re.IGNORECASE,
)


# ============================================================
# Header utilities
# ============================================================

def _decode_header_value(value: Any) -> str:
    """
    Safely convert an email header value into a Unicode string.
    """

    if value is None:
        return ""

    try:
        return str(value)
    except Exception:
        try:
            return (
                bytes(str(value), "utf-8", errors="replace")
                .decode("utf-8", errors="replace")
            )
        except Exception:
            return ""


def _extract_domain_from_email(value: str) -> str | None:
    """
    Extract a domain from an email address/header value.
    """

    if not value:
        return None

    matches = EMAIL_PATTERN.findall(value)

    if not matches:
        return None

    email_address = matches[0]

    if "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


def _extract_email_addresses(value: str) -> list[str]:
    """
    Extract email addresses from a header.
    """

    if not value:
        return []

    return EMAIL_PATTERN.findall(value)


# ============================================================
# URL utilities
# ============================================================

def _clean_url(url: str) -> str:
    """
    Normalize a URL extracted from email content.

    Handles:
        https://example.com/login
        https://example.com/login.
        [text](https://example.com/login)

    Does NOT resolve redirects or contact the URL.
    """

    if not url:
        return ""

    url = url.strip()

    # --------------------------------------------------------
    # Markdown URL
    # Example:
    # [Verify](https://example.com/login)
    # --------------------------------------------------------

    markdown_match = MARKDOWN_URL_PATTERN.search(url)

    if markdown_match:
        url = markdown_match.group(1)

    # --------------------------------------------------------
    # Remove accidental Markdown artifacts
    # --------------------------------------------------------

    if url.startswith("["):
        url = url.lstrip("[")

    if "](" in url:
        url = url.split("](", 1)[-1]

    if url.endswith(")"):
        url = url[:-1]

    # --------------------------------------------------------
    # Remove punctuation attached to URL
    # --------------------------------------------------------

    url = url.rstrip(
        ".,;:!?]}\"'"
    )

    return url.strip()


def _extract_urls(text: str) -> list[str]:
    """
    Extract unique HTTP/HTTPS URLs.

    Supports:
        - Plain URLs
        - URLs followed by punctuation
        - Markdown-style links

    Returns normalized URLs only.
    """

    if not text:
        return []

    urls: list[str] = []

    # --------------------------------------------------------
    # Markdown links
    # --------------------------------------------------------

    for match in MARKDOWN_URL_PATTERN.findall(text):

        cleaned = _clean_url(match)

        if (
            cleaned
            and cleaned.startswith(
                ("http://", "https://")
            )
            and cleaned not in urls
        ):
            urls.append(cleaned)

    # --------------------------------------------------------
    # Normal URLs
    # --------------------------------------------------------

    for match in URL_PATTERN.findall(text):

        cleaned = _clean_url(match)

        if (
            cleaned
            and cleaned.startswith(
                ("http://", "https://")
            )
            and cleaned not in urls
        ):
            urls.append(cleaned)

    return urls


# ============================================================
# Cryptographic utilities
# ============================================================

def _calculate_sha256(data: bytes) -> str:
    """
    Calculate SHA-256 hash.
    """

    return hashlib.sha256(data).hexdigest()


# ============================================================
# Attachment utilities
# ============================================================

def _get_attachment_filename(
    part: Message,
) -> str | None:
    """
    Safely obtain an attachment filename.
    """

    filename = part.get_filename()

    if not filename:
        return None

    return _decode_header_value(filename)


def _extract_attachment(
    part: Message,
) -> dict[str, Any]:
    """
    Extract attachment metadata and SHA-256 hash.

    Important:
        The attachment is NOT executed.
    """

    try:
        payload = part.get_payload(
            decode=True
        )
    except Exception:
        payload = None

    if payload is None:
        payload = b""

    filename = _get_attachment_filename(part)

    content_type = part.get_content_type()

    guessed_type = None

    if filename:
        guessed_type, _ = mimetypes.guess_type(
            filename
        )

    return {
        "filename": filename,
        "content_type": content_type,
        "guessed_type": guessed_type,
        "content_disposition": (
            part.get_content_disposition()
        ),
        "size": len(payload),
        "sha256": _calculate_sha256(payload),
        "_content": payload,
    }



# ============================================================
# MIME body extraction
# ============================================================

def _extract_body_parts(
    message: Message,
) -> tuple[str, str]:
    """
    Extract plain-text and HTML bodies.

    Multipart emails are traversed recursively.
    Attachments are skipped here and handled separately.
    """

    text_parts: list[str] = []
    html_parts: list[str] = []

    # --------------------------------------------------------
    # Multipart email
    # --------------------------------------------------------

    if message.is_multipart():

        for part in message.walk():

            # Skip multipart containers.
            if part.is_multipart():
                continue

            disposition = (
                part.get_content_disposition()
            )

            # Attachments are handled separately.
            if disposition == "attachment":
                continue

            content_type = (
                part.get_content_type()
            )

            try:
                content = part.get_content()

            except Exception:

                try:
                    payload = part.get_payload(
                        decode=True
                    )
                except Exception:
                    payload = None

                if payload is None:
                    continue

                charset = (
                    part.get_content_charset()
                    or "utf-8"
                )

                try:
                    content = payload.decode(
                        charset,
                        errors="replace",
                    )

                except (
                    LookupError,
                    UnicodeDecodeError,
                ):
                    content = payload.decode(
                        "utf-8",
                        errors="replace",
                    )

            if not isinstance(content, str):
                continue

            if content_type == "text/plain":

                text_parts.append(content)

            elif content_type == "text/html":

                html_parts.append(content)

    # --------------------------------------------------------
    # Single-part email
    # --------------------------------------------------------

    else:

        content_type = (
            message.get_content_type()
        )

        try:
            content = message.get_content()

        except Exception:
            content = ""

        if isinstance(content, str):

            if content_type == "text/plain":

                text_parts.append(content)

            elif content_type == "text/html":

                html_parts.append(content)

    return (
        "\n\n".join(text_parts).strip(),
        "\n\n".join(html_parts).strip(),
    )


# ============================================================
# Attachment extraction
# ============================================================

def _extract_attachments(
    message: Message,
) -> list[dict[str, Any]]:
    """
    Extract metadata for all MIME attachments.

    Files are never executed.
    """

    attachments: list[dict[str, Any]] = []

    for part in message.walk():

        if part.is_multipart():
            continue

        disposition = (
            part.get_content_disposition()
        )

        filename = _get_attachment_filename(
            part
        )

        # Attachment if explicitly marked OR
        # if a filename exists.
        if (
            disposition == "attachment"
            or filename
        ):

            try:
                attachment = _extract_attachment(
                    part
                )

                attachments.append(
                    attachment
                )

            except Exception as exc:

                attachments.append(
                    {
                        "filename": filename,
                        "content_type": (
                            part.get_content_type()
                        ),
                        "guessed_type": None,
                        "content_disposition": (
                            disposition
                        ),
                        "size": 0,
                        "sha256": None,
                        "error": str(exc),
                    }
                )

    return attachments


# ============================================================
# Header extraction
# ============================================================

def _extract_headers(
    message: Message,
) -> dict[str, Any]:
    """
    Extract security-relevant email headers.

    This function does not determine whether the headers
    are trustworthy. That is the job of header_analyzer.py.
    """

    from_header = _decode_header_value(
        message.get("From")
    )

    to_header = _decode_header_value(
        message.get("To")
    )

    cc_header = _decode_header_value(
        message.get("Cc")
    )

    bcc_header = _decode_header_value(
        message.get("Bcc")
    )

    reply_to = _decode_header_value(
        message.get("Reply-To")
    )

    return_path = _decode_header_value(
        message.get("Return-Path")
    )

    subject = _decode_header_value(
        message.get("Subject")
    )

    message_id = _decode_header_value(
        message.get("Message-ID")
    )

    date = _decode_header_value(
        message.get("Date")
    )

    sender_domain = (
        _extract_domain_from_email(
            from_header
        )
    )

    reply_to_domain = (
        _extract_domain_from_email(
            reply_to
        )
    )

    return_path_domain = (
        _extract_domain_from_email(
            return_path
        )
    )

    return {
        "from": from_header,
        "to": to_header,
        "cc": cc_header,
        "bcc": bcc_header,
        "reply_to": reply_to,
        "return_path": return_path,
        "subject": subject,
        "message_id": message_id,
        "date": date,

        "from_addresses": (
            _extract_email_addresses(
                from_header
            )
        ),

        "to_addresses": (
            _extract_email_addresses(
                to_header
            )
        ),

        "cc_addresses": (
            _extract_email_addresses(
                cc_header
            )
        ),

        "reply_to_addresses": (
            _extract_email_addresses(
                reply_to
            )
        ),

        "from_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
    }


# ============================================================
# Authentication headers
# ============================================================

def _extract_authentication_headers(
    message: Message,
) -> dict[str, Any]:
    """
    Extract authentication-related headers.

    These values are evidence only.

    The parser does NOT verify SPF/DKIM/DMARC itself.
    """

    authentication_results = (
        _decode_header_value(
            message.get(
                "Authentication-Results"
            )
        )
    )

    received_spf = _decode_header_value(
        message.get(
            "Received-SPF"
        )
    )

    dkim_signature = _decode_header_value(
        message.get(
            "DKIM-Signature"
        )
    )

    return {
        "authentication_results": (
            authentication_results
        ),
        "received_spf": received_spf,
        "dkim_signature": dkim_signature,

        "authentication_results_present": bool(
            authentication_results
        ),

        "received_spf_present": bool(
            received_spf
        ),

        "dkim_signature_present": bool(
            dkim_signature
        ),
    }


# ============================================================
# Received headers
# ============================================================

def _extract_received_headers(
    message: Message,
) -> list[str]:
    """
    Extract all Received headers.

    Header analysis will later inspect these for routing
    anomalies and suspicious infrastructure.
    """

    values = message.get_all(
        "Received",
        [],
    )

    return [
        _decode_header_value(value)
        for value in values
    ]


# ============================================================
# Main parser
# ============================================================

def parse_email(
    file_path: str | Path,
) -> dict[str, Any]:
    """
    Parse a .eml file.

    Returns a normalized dictionary containing:

        metadata
        headers
        authentication
        body
        urls
        attachments
        mime
        statistics

    No external network requests are made.
    """

    path = Path(file_path)

    if not path.exists():

        raise FileNotFoundError(
            f"Email file not found: {path}"
        )

    if not path.is_file():

        raise ValueError(
            f"Path is not a file: {path}"
        )

    # --------------------------------------------------------
    # Read email
    # --------------------------------------------------------

    with path.open(
        "rb"
    ) as email_file:

        message = BytesParser(
            policy=policy.default
        ).parse(
            email_file
        )

    # --------------------------------------------------------
    # Headers
    # --------------------------------------------------------

    headers = _extract_headers(
        message
    )

    authentication = (
        _extract_authentication_headers(
            message
        )
    )

    received_headers = (
        _extract_received_headers(
            message
        )
    )

    # --------------------------------------------------------
    # Bodies
    # --------------------------------------------------------

    text_body, html_body = (
        _extract_body_parts(
            message
        )
    )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    text_urls = _extract_urls(
        text_body
    )

    html_urls = _extract_urls(
        html_body
    )

    all_urls: list[str] = []

    for url in (
        text_urls + html_urls
    ):

        if url not in all_urls:

            all_urls.append(url)

    # --------------------------------------------------------
    # Attachments
    # --------------------------------------------------------

    attachments = (
        _extract_attachments(
            message
        )
    )

    # --------------------------------------------------------
    # MIME information
    # --------------------------------------------------------

    content_type = (
        message.get_content_type()
    )

    mime_version = _decode_header_value(
        message.get(
            "MIME-Version"
        )
    )

    multipart = message.is_multipart()

    # --------------------------------------------------------
    # Basic statistics
    # --------------------------------------------------------

    statistics = {
        "text_length": len(text_body),
        "html_length": len(html_body),
        "url_count": len(all_urls),
        "attachment_count": len(
            attachments
        ),
        "received_header_count": len(
            received_headers
        ),
    }

    # --------------------------------------------------------
    # Final normalized structure
    # --------------------------------------------------------

    return {
        "parser": {
            "name": "MailSentinel Email Parser",
            "version": "1.0",
        },

        "file": {
            "name": path.name,
            "path": str(path),
            "size": path.stat().st_size,
        },

        "metadata": {
            "from": headers["from"],
            "to": headers["to"],
            "cc": headers["cc"],
            "bcc": headers["bcc"],
            "reply_to": headers["reply_to"],
            "return_path": headers["return_path"],
            "subject": headers["subject"],
            "date": headers["date"],
            "message_id": headers["message_id"],

            "from_domain": (
                headers["from_domain"]
            ),

            "reply_to_domain": (
                headers["reply_to_domain"]
            ),

            "return_path_domain": (
                headers["return_path_domain"]
            ),
        },

        "headers": {
            **headers,

            "received": (
                received_headers
            ),
        },

        "authentication": authentication,

        "body": {
            "text": text_body,
            "html": html_body,
        },

        "urls": {
            "count": len(all_urls),
            "items": all_urls,

            "text_urls": text_urls,
            "html_urls": html_urls,
        },

        "attachments": {
            "count": len(attachments),
            "items": attachments,
        },

        "mime": {
            "content_type": content_type,
            "mime_version": mime_version,
            "multipart": multipart,
        },

        "statistics": statistics,
    }


# ============================================================
# Command-line interface
# ============================================================

def _print_summary(
    result: dict[str, Any],
) -> None:
    """
    Print a human-readable parser summary.
    """

    metadata = result.get(
        "metadata",
        {}
    )

    urls = result.get(
        "urls",
        {}
    )

    attachments = result.get(
        "attachments",
        {}
    )

    mime = result.get(
        "mime",
        {}
    )

    print(
        "\n========== EMAIL PARSER =========="
    )

    print(
        f"Subject: {metadata.get('subject', '')}"
    )

    print(
        f"From: {metadata.get('from', '')}"
    )

    print(
        f"To: {metadata.get('to', '')}"
    )

    print(
        f"Reply-To: {metadata.get('reply_to', '')}"
    )

    print(
        f"From Domain: "
        f"{metadata.get('from_domain', '')}"
    )

    print(
        f"Reply-To Domain: "
        f"{metadata.get('reply_to_domain', '')}"
    )

    print(
        f"URLs: {urls.get('count', 0)}"
    )

    for url in urls.get(
        "items",
        [],
    ):

        print(
            f"  - {url}"
        )

    print(
        f"Attachments: "
        f"{attachments.get('count', 0)}"
    )

    for attachment in attachments.get(
        "items",
        [],
    ):

        print(
            "  - "
            f"{attachment.get('filename')}"
            f" | "
            f"{attachment.get('content_type')}"
            f" | "
            f"{attachment.get('size')} bytes"
        )

    print(
        f"Multipart: "
        f"{mime.get('multipart', False)}"
    )

    print(
        "==================================\n"
    )


def main() -> None:
    """
    Command-line entry point.
    """

    import argparse
    import json

    parser = argparse.ArgumentParser(
        description=(
            "MailSentinel .eml security parser"
        )
    )

    parser.add_argument(
        "email_file",
        help="Path to .eml file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print complete JSON output",
    )

    args = parser.parse_args()

    try:

        result = parse_email(
            args.email_file
        )

        if args.json:

            print(
                json.dumps(
                    result,
                    indent=2,
                    ensure_ascii=False,
                )
            )

        else:

            _print_summary(
                result
            )

    except Exception as exc:

        print(
            f"ERROR: {exc}"
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
