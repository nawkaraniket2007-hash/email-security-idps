"""
MailSentinel - Main Application

Runs all available email security analyzers against
a single .eml file and combines their results using
the risk engine.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from backend.modules.email_parser import parse_email
from backend.modules.header_analyzer import analyze_headers
from backend.modules.url_analyzer import analyze_urls
from backend.modules.html_analyzer import analyze_html
from backend.modules.attachment_analyzer import analyze_attachments
from backend.modules.risk_engine import analyze_risk
from backend.modules.ai_analyzer import analyze_with_ai

def _run_analyzer(
    name: str,
    function: Any,
    input_data: Any,
) -> dict[str, Any]:
    """
    Safely execute one analyzer.

    A failure in one analyzer should not silently
    destroy the complete analysis.
    """

    try:
        result = function(input_data)

        if isinstance(result, dict):
            return result

        return {
            "analyzer": name,
            "version": "unknown",
            "score": 0,
            "status": "error",
            "findings": [],
            "error": (
                "Analyzer returned a non-dictionary result."
            ),
        }

    except Exception as exc:
        return {
            "analyzer": name,
            "version": "unknown",
            "score": 0,
            "status": "error",
            "findings": [],
            "error": str(exc),
        }


def analyze_email(
    email_path: str | Path,
) -> dict[str, Any]:
    """
    Run the complete MailSentinel analysis pipeline.

    Pipeline:

        .eml
          ↓
        parser
          ↓
        header analyzer
        URL analyzer
        HTML analyzer
        attachment analyzer
          ↓
        risk engine
    """

    path = Path(email_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Email file not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Path is not a file: {path}"
        )

    # --------------------------------------------------------
    # Parse email
    # --------------------------------------------------------

    parsed_email = parse_email(
        str(path)
    )

    if not isinstance(
        parsed_email,
        dict,
    ):
        raise RuntimeError(
            "email_parser returned invalid data."
        )

    # --------------------------------------------------------
    # Header analyzer
    # --------------------------------------------------------

    header_result = _run_analyzer(
        "header_analyzer",
        analyze_headers,
        parsed_email,
    )

    # --------------------------------------------------------
    # URL analyzer
    # --------------------------------------------------------

    url_result = _run_analyzer(
        "url_analyzer",
        analyze_urls,
        parsed_email,
    )

    # --------------------------------------------------------
    # HTML analyzer
    # --------------------------------------------------------

    html_result = _run_analyzer(
        "html_analyzer",
        analyze_html,
        parsed_email,
    )

    # --------------------------------------------------------
    # Attachment analyzer
    # --------------------------------------------------------

    attachment_result = _run_analyzer(
    "attachment_analyzer",
    analyze_attachments,
    parsed_email.get("attachments", {}).get("items", []),
)

    # --------------------------------------------------------
    # Combine analyzer results
    # --------------------------------------------------------

    analyzer_results = {
        "header_analyzer": header_result,
        "url_analyzer": url_result,
        "html_analyzer": html_result,
        "attachment_analyzer": attachment_result,
    }

    # --------------------------------------------------------
    # Risk engine
    # --------------------------------------------------------

    risk_result = analyze_risk(
        analyzer_results
    )


        # --------------------------------------------------------
    # AI security analysis
    # --------------------------------------------------------

    ai_result = analyze_with_ai(
        parsed_email,
        analyzer_results,
        risk_result,
    )

    # --------------------------------------------------------
    # Final application result
    # --------------------------------------------------------

    return {
        "application": {
            "name": "MailSentinel",
            "version": "1.0",
        },
        "email": {
            "file": str(path),
            "size": path.stat().st_size,
        },
        "parser": parsed_email,
        "analyzers": analyzer_results,
        "risk": risk_result,
        "ai_analysis": ai_result,
    }

def main() -> int:
    """
    Command-line entry point.
    """

    parser = argparse.ArgumentParser(
        description=(
            "MailSentinel Email Security Analysis"
        )
    )

    parser.add_argument(
        "email",
        help="Path to the .eml file",
    )

    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )

    args = parser.parse_args()

    try:
        result = analyze_email(
            args.email
        )

    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": str(exc),
                },
                indent=2 if args.pretty else None,
            ),
            file=sys.stderr,
        )

        return 1

    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            default=str,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
