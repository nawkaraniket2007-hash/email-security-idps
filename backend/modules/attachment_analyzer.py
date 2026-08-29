"""
MailSentinel - Attachment Analyzer

Purpose:
    Perform safe static analysis of email attachments.

Security:
    - Never executes attachments.
    - Never launches external programs.
    - Uses filename, MIME type, SHA-256 and magic-byte analysis.
    - Detects suspicious extensions and double extensions.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
from pathlib import Path
from typing import Any


ANALYZER_NAME = "attachment_analyzer"
ANALYZER_VERSION = "2.0"


# ============================================================
# Extension classifications
# ============================================================

EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
    ".sys",
    ".cpl",
    ".ocx",
    ".drv",
}

SCRIPT_EXTENSIONS = {
    ".ps1",
    ".psm1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".sh",
}

MACRO_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
    ".ppsm",
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
}

DISK_IMAGE_EXTENSIONS = {
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
}

DANGEROUS_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS
    | SCRIPT_EXTENSIONS
)

SUSPICIOUS_DOCUMENT_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
    ".ppsm",
}


# ============================================================
# Basic utilities
# ============================================================

def normalize_extension(filename: str) -> str:
    """Return the final file extension in lowercase."""

    return Path(filename).suffix.lower()


def get_all_extensions(filename: str) -> list[str]:
    """Return all extensions from a filename."""

    return [
        extension.lower()
        for extension in Path(filename).suffixes
    ]


def guess_mime_type(filename: str) -> str | None:
    """Guess MIME type using the filename."""

    mime_type, _ = mimetypes.guess_type(filename)

    return mime_type


# ============================================================
# Magic-byte / file signature detection
# ============================================================

def detect_file_signature(data: bytes) -> str | None:
    """
    Detect common file types using magic bytes.

    This function does NOT execute the file.
    """

    if not data:
        return None

    signatures = [
        (b"MZ", "PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"%PDF-", "PDF document"),
        (b"PK\x03\x04", "ZIP / OOXML archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF87a", "GIF image"),
        (b"GIF89a", "GIF image"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ]

    for magic, description in signatures:
        if data.startswith(magic):
            return description

    return None


# ============================================================
# Double-extension detection
# ============================================================

def detect_double_extension(
    filename: str,
) -> bool:
    """
    Detect patterns such as:

        invoice.pdf.exe
        document.docx.scr
        photo.jpg.js
    """

    extensions = get_all_extensions(filename)

    if len(extensions) < 2:
        return False

    final_extension = extensions[-1]

    if final_extension in DANGEROUS_EXTENSIONS:
        previous_extensions = extensions[:-1]

        document_like = {
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".txt",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".zip",
        }

        if any(
            extension in document_like
            for extension in previous_extensions
        ):
            return True

    return False


# ============================================================
# Filename analysis
# ============================================================

def analyze_filename(
    filename: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    extension = normalize_extension(filename)

    all_extensions = get_all_extensions(filename)

    is_executable = (
        extension in EXECUTABLE_EXTENSIONS
    )

    is_script = (
        extension in SCRIPT_EXTENSIONS
    )

    is_macro_document = (
        extension in MACRO_EXTENSIONS
    )

    is_archive = (
        extension in ARCHIVE_EXTENSIONS
    )

    is_disk_image = (
        extension in DISK_IMAGE_EXTENSIONS
    )

    double_extension = detect_double_extension(
        filename
    )

    characteristics = {
        "extension": extension,
        "all_extensions": all_extensions,
        "double_extension": double_extension,
        "executable": is_executable,
        "script": is_script,
        "macro_enabled_document": is_macro_document,
        "archive": is_archive,
        "disk_image": is_disk_image,
    }

    # --------------------------------------------------------
    # Double extension
    # --------------------------------------------------------

    if double_extension:
        findings.append(
            {
                "indicator": "double_extension",
                "severity": "high",
                "score": 20,
                "description": (
                    "The attachment uses a double-extension "
                    "pattern that may disguise an executable "
                    "or script as a document."
                ),
            }
        )

    # --------------------------------------------------------
    # Executable
    # --------------------------------------------------------

    if is_executable:
        findings.append(
            {
                "indicator": "executable_attachment",
                "severity": "high",
                "score": 20,
                "description": (
                    f"The attachment uses the executable "
                    f"extension '{extension}'."
                ),
            }
        )

    # --------------------------------------------------------
    # Script
    # --------------------------------------------------------

    if is_script:
        findings.append(
            {
                "indicator": "script_attachment",
                "severity": "high",
                "score": 18,
                "description": (
                    f"The attachment uses the scripting "
                    f"extension '{extension}'."
                ),
            }
        )

    # --------------------------------------------------------
    # Macro-enabled Office document
    # --------------------------------------------------------

    if is_macro_document:
        findings.append(
            {
                "indicator": "macro_enabled_document",
                "severity": "medium",
                "score": 12,
                "description": (
                    f"The attachment uses the macro-enabled "
                    f"Office extension '{extension}'."
                ),
            }
        )

    # --------------------------------------------------------
    # Disk image
    # --------------------------------------------------------

    if is_disk_image:
        findings.append(
            {
                "indicator": "disk_image_attachment",
                "severity": "medium",
                "score": 10,
                "description": (
                    f"The attachment uses the disk-image "
                    f"extension '{extension}'."
                ),
            }
        )

    return findings, characteristics


# ============================================================
# File signature analysis
# ============================================================

def analyze_file_signature(
    filename: str,
    data: bytes,
) -> tuple[
    str | None,
    list[dict[str, Any]],
]:

    findings: list[dict[str, Any]] = []

    signature = detect_file_signature(data)

    if not signature:
        return None, findings

    extension = normalize_extension(filename)

    # --------------------------------------------------------
    # PE executable
    # --------------------------------------------------------

    if signature == "PE executable":

        if extension not in EXECUTABLE_EXTENSIONS:
            findings.append(
                {
                    "indicator": "executable_signature_mismatch",
                    "severity": "critical",
                    "score": 30,
                    "description": (
                        "The attachment contains a Windows "
                        "PE executable signature even though "
                        "the filename does not use a normal "
                        "executable extension."
                    ),
                }
            )

    # --------------------------------------------------------
    # ELF executable
    # --------------------------------------------------------

    elif signature == "ELF executable":

        if extension not in EXECUTABLE_EXTENSIONS:
            findings.append(
                {
                    "indicator": "elf_signature_mismatch",
                    "severity": "critical",
                    "score": 30,
                    "description": (
                        "The attachment contains a Linux ELF "
                        "executable signature but the filename "
                        "does not use an executable extension."
                    ),
                }
            )

    # --------------------------------------------------------
    # PDF mismatch
    # --------------------------------------------------------

    elif signature == "PDF document":

        if extension != ".pdf":
            findings.append(
                {
                    "indicator": "pdf_signature_mismatch",
                    "severity": "high",
                    "score": 20,
                    "description": (
                        "The file signature indicates a PDF "
                        "document but the filename does not "
                        "use the .pdf extension."
                    ),
                }
            )

    return signature, findings


# ============================================================
# Single attachment analysis
# ============================================================

def analyze_attachment(
    attachment: dict[str, Any],
) -> dict[str, Any]:

    filename = str(
        attachment.get(
            "filename",
            "unknown",
        )
    )

    declared_mime = attachment.get(
        "content_type"
    )

    size = attachment.get(
        "size",
        0,
    )

    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0

    # --------------------------------------------------------
    # Raw content
    # --------------------------------------------------------

    raw_content = attachment.get(
        "_content",
        b"",
    )

    if not isinstance(raw_content, bytes):
        raw_content = b""

    # --------------------------------------------------------
    # Filename analysis
    # --------------------------------------------------------

    findings, characteristics = analyze_filename(
        filename
    )

    # --------------------------------------------------------
    # Signature analysis
    # --------------------------------------------------------

    signature, signature_findings = (
        analyze_file_signature(
            filename,
            raw_content,
        )
    )

    findings.extend(
        signature_findings
    )

    characteristics[
        "file_signature"
    ] = signature

    # --------------------------------------------------------
    # MIME information
    # --------------------------------------------------------

    guessed_mime = guess_mime_type(
        filename
    )

    characteristics[
        "mime_mismatch"
    ] = False

    if (
        declared_mime
        and guessed_mime
        and declared_mime != "application/octet-stream"
        and declared_mime != guessed_mime
    ):
        characteristics[
            "mime_mismatch"
        ] = True

        findings.append(
            {
                "indicator": "mime_type_mismatch",
                "severity": "medium",
                "score": 8,
                "description": (
                    f"The declared MIME type "
                    f"'{declared_mime}' differs from "
                    f"the filename-based MIME type "
                    f"'{guessed_mime}'."
                ),
            }
        )

    # --------------------------------------------------------
    # Large attachment
    # --------------------------------------------------------

    if size > 50 * 1024 * 1024:
        findings.append(
            {
                "indicator": "large_attachment",
                "severity": "low",
                "score": 3,
                "description": (
                    "The attachment is larger than 50 MB. "
                    "Large size alone does not indicate malware."
                ),
            }
        )

    # --------------------------------------------------------
    # Calculate score
    # --------------------------------------------------------

    score = sum(
        int(
            finding.get(
                "score",
                0,
            )
        )
        for finding in findings
    )

    score = min(
        score,
        100,
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if score >= 60:
        status = "critical"

    elif score >= 40:
        status = "high_risk"

    elif score >= 20:
        status = "suspicious"

    elif score > 0:
        status = "low_risk"

    else:
        status = "normal"

    return {
        "filename": filename,
        "size": size,
        "sha256": attachment.get(
            "sha256"
        ),
        "declared_mime": declared_mime,
        "guessed_mime": guessed_mime,
        "characteristics": characteristics,
        "findings": findings,
        "score": score,
        "status": status,
    }


# ============================================================
# Complete attachment analysis
# ============================================================

def analyze_attachments(
    attachments: list[dict[str, Any]],
) -> dict[str, Any]:

    if not isinstance(
        attachments,
        list,
    ):
        raise TypeError(
            "attachments must be a list"
        )

    results: list[
        dict[str, Any]
    ] = []

    for attachment in attachments:

        if not isinstance(
            attachment,
            dict,
        ):
            continue

        result = analyze_attachment(
            attachment
        )

        results.append(
            result
        )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    critical_count = sum(
        1
        for result in results
        if result["status"] == "critical"
    )

    high_risk_count = sum(
        1
        for result in results
        if result["status"] == "high_risk"
    )

    suspicious_count = sum(
        1
        for result in results
        if result["status"] == "suspicious"
    )

    low_risk_count = sum(
        1
        for result in results
        if result["status"] == "low_risk"
    )

    # --------------------------------------------------------
    # Overall score
    # --------------------------------------------------------

    total_score = sum(
        result["score"]
        for result in results
    )

    total_score = min(
        total_score,
        100,
    )

    # --------------------------------------------------------
    # Overall status
    # --------------------------------------------------------

    if critical_count > 0:
        overall_status = "critical"

    elif high_risk_count > 0:
        overall_status = "high_risk"

    elif suspicious_count > 0:
        overall_status = "suspicious"

    elif low_risk_count > 0:
        overall_status = "low_risk"

    else:
        overall_status = "normal"

    # --------------------------------------------------------
    # Flatten findings
    # --------------------------------------------------------

    all_findings: list[
        dict[str, Any]
    ] = []

    for result in results:

        for finding in result.get(
            "findings",
            [],
        ):

            finding_copy = dict(
                finding
            )

            finding_copy[
                "filename"
            ] = result[
                "filename"
            ]

            all_findings.append(
                finding_copy
            )

    return {
        "analyzer": ANALYZER_NAME,
        "version": ANALYZER_VERSION,

        "statistics": {
            "attachment_count": len(
                results
            ),
            "critical_attachments": critical_count,
            "high_risk_attachments": high_risk_count,
            "suspicious_attachments": suspicious_count,
            "low_risk_attachments": low_risk_count,
        },

        "attachments": results,

        "findings": all_findings,

        "score": total_score,

        "status": overall_status,
    }


# ============================================================
# CLI
# ============================================================

def main() -> None:

    parser = argparse.ArgumentParser(
        description=(
            "MailSentinel Attachment Analyzer"
        )
    )

    parser.add_argument(
        "email",
        help="Path to .eml file",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    args = parser.parse_args()

    try:

        from .email_parser import parse_email

        parsed = parse_email(
            args.email
        )

        attachment_data = parsed.get(
            "attachments",
            {},
        )

        if isinstance(
            attachment_data,
            dict,
        ):
            attachments = (
                attachment_data.get(
                    "items",
                    [],
                )
            )
        else:
            attachments = attachment_data

        result = analyze_attachments(
            attachments
        )

        print(
            json.dumps(
                result,
                indent=2
                if args.pretty
                else None,
                ensure_ascii=False,
            )
        )

    except Exception as exc:

        error = {
            "analyzer": ANALYZER_NAME,
            "version": ANALYZER_VERSION,
            "error": str(exc),
        }

        print(
            json.dumps(
                error,
                indent=2,
            )
        )

        raise SystemExit(1)


if __name__ == "__main__":
    main()
