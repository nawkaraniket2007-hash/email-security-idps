from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)


def generate_report(
    analysis: dict[str, Any],
    output_path: str | Path,
) -> str:
    """
    Generate a professional MailSentinel PDF security report.
    """

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    application = analysis.get("application", {})
    email = analysis.get("email", {})
    risk = analysis.get("risk", {})
    ai = analysis.get("ai_analysis", {})
    analyzers = analysis.get("analyzers", {})
    parser = analysis.get("parser", {})

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        alignment=TA_CENTER,
        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(
        "Subtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_CENTER,
        spaceAfter=18,
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=12,
        spaceAfter=8,
    )

    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=13,
        spaceAfter=6,
    )

    small_style = ParagraphStyle(
        "Small",
        parent=styles["BodyText"],
        fontSize=8,
        leading=11,
    )

    story = []

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    story.append(Paragraph("MAILSENTINEL", title_style))
    story.append(
        Paragraph(
            "Email Security & Threat Analysis Report",
            subtitle_style,
        )
    )

    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    report_info = [
        ["Report Generated", generated_at],
        ["Application", application.get("name", "MailSentinel")],
        ["Version", application.get("version", "1.0")],
        ["Analyzed File", email.get("file", "Unknown")],
    ]

    table = Table(report_info, colWidths=[48 * mm, 125 * mm])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#162033")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(table)
    story.append(Spacer(1, 10))

    # --------------------------------------------------------
    # Executive Security Verdict
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "1. Executive Security Verdict",
            heading_style,
        )
    )

    verdict_data = [
        ["Risk Score", str(risk.get("score", 0))],
        ["Classification", str(risk.get("classification", "unknown")).upper()],
        ["Confidence", str(risk.get("confidence", "unknown")).upper()],
        ["Recommended Action", str(risk.get("recommended_action", "unknown")).upper()],
        ["AI Threat Level", str(ai.get("threat_level", "unknown")).upper()],
        ["AI Confidence", str(ai.get("confidence", "unknown")).upper()],
        ["AI Malicious Verdict", str(ai.get("is_malicious", "unknown")).upper()],
    ]

    table = Table(verdict_data, colWidths=[65 * mm, 108 * mm])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#162033")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("PADDING", (0, 0), (-1, -1), 7),
            ]
        )
    )

    story.append(table)

    # --------------------------------------------------------
    # AI Summary
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "2. AI Security Analysis",
            heading_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>Summary:</b> {ai.get('summary', 'No AI summary available.')}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>User Explanation:</b> "
            f"{ai.get('user_explanation', 'No explanation available.')}",
            body_style,
        )
    )

    story.append(
        Paragraph(
            f"<b>AI Recommended Action:</b> "
            f"{ai.get('recommended_action', 'No recommendation available.')}",
            body_style,
        )
    )

    # --------------------------------------------------------
    # AI Key Findings
    # --------------------------------------------------------

    key_findings = ai.get("key_findings", [])

    if key_findings:
        story.append(
            Paragraph(
                "AI Key Findings",
                ParagraphStyle(
                    "SubHeading",
                    parent=heading_style,
                    fontSize=11,
                ),
            )
        )

        for finding in key_findings:
            story.append(
                Paragraph(
                    f"• {finding}",
                    body_style,
                )
            )

    # --------------------------------------------------------
    # Risk Findings
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "3. Deterministic Risk Findings",
            heading_style,
        )
    )

    findings = risk.get("findings", [])

    if findings:
        finding_rows = [
            ["Severity", "Analyzer", "Indicator", "Score", "Description"]
        ]

        for finding in findings:
            finding_rows.append(
                [
                    str(finding.get("severity", "unknown")),
                    str(finding.get("analyzer", "unknown")),
                    str(finding.get("indicator", "unknown")),
                    str(finding.get("score", 0)),
                    Paragraph(
                        str(finding.get("description", "")),
                        small_style,
                    ),
                ]
            )

        table = Table(
            finding_rows,
            colWidths=[
                22 * mm,
                30 * mm,
                34 * mm,
                15 * mm,
                72 * mm,
            ],
            repeatRows=1,
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162033")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(table)

    else:
        story.append(
            Paragraph(
                "No deterministic risk findings were reported.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # Analyzer Results
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "4. Analyzer Results",
            heading_style,
        )
    )

    analyzer_rows = [
        ["Analyzer", "Score", "Status"]
    ]

    for name, result in analyzers.items():
        analyzer_rows.append(
            [
                name,
                str(result.get("score", 0)),
                str(result.get("status", "unknown")),
            ]
        )

    table = Table(
        analyzer_rows,
        colWidths=[80 * mm, 35 * mm, 58 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(table)

    # --------------------------------------------------------
    # Attachment Analysis
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "5. Attachment Analysis",
            heading_style,
        )
    )

    attachment_result = analyzers.get(
        "attachment_analyzer",
        {},
    )

    attachments = attachment_result.get(
        "attachments",
        parser.get("attachments", {}).get("items", []),
    )

    if attachments:
        attachment_rows = [
            ["Filename", "Size", "SHA-256", "Risk"]
        ]

        for attachment in attachments:
            attachment_rows.append(
                [
                    str(attachment.get("filename", "unknown")),
                    f"{attachment.get('size', 0)} bytes",
                    str(attachment.get("sha256", "unknown")),
                    str(
                        attachment.get(
                            "status",
                            "unknown",
                        )
                    ),
                ]
            )

        table = Table(
            attachment_rows,
            colWidths=[
                45 * mm,
                25 * mm,
                72 * mm,
                31 * mm,
            ],
            repeatRows=1,
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162033")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("PADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )

        story.append(table)

    else:
        story.append(
            Paragraph(
                "No attachments detected.",
                body_style,
            )
        )

    # --------------------------------------------------------
    # Email Metadata
    # --------------------------------------------------------

    story.append(
        Paragraph(
            "6. Email Metadata",
            heading_style,
        )
    )

    metadata = parser.get("metadata", {})

    metadata_rows = [
        ["Field", "Value"],
        ["From", str(metadata.get("from", ""))],
        ["To", str(metadata.get("to", ""))],
        ["Subject", str(metadata.get("subject", ""))],
        ["Date", str(metadata.get("date", ""))],
        ["Reply-To", str(metadata.get("reply_to", ""))],
        ["Return-Path", str(metadata.get("return_path", ""))],
        ["Message-ID", str(metadata.get("message_id", ""))],
    ]

    table = Table(
        metadata_rows,
        colWidths=[45 * mm, 128 * mm],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#162033")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )

    story.append(table)

    # --------------------------------------------------------
    # Risk Explanations
    # --------------------------------------------------------

    explanations = risk.get("explanations", [])

    if explanations:
        story.append(
            Paragraph(
                "7. Risk Explanations",
                heading_style,
            )
        )

        for explanation in explanations:
            story.append(
                Paragraph(
                    f"• {explanation}",
                    body_style,
                )
            )

    # --------------------------------------------------------
    # Footer / Disclaimer
    # --------------------------------------------------------

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            "MailSentinel provides automated security analysis. "
            "Results should be treated as security intelligence and "
            "not as an absolute guarantee that an email is malicious "
            "or legitimate.",
            small_style,
        )
    )

    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="MailSentinel Security Report",
        author="MailSentinel",
    )

    doc.build(story)

    return str(output)
