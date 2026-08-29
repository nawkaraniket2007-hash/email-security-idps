from __future__ import annotations
import json
import os
import sqlite3
from pathlib import Path
from typing import Any


# ============================================================
# Database configuration
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATABASE_PATH = Path(
    os.environ.get(
        "MAILSENTINEL_DATABASE",
        BASE_DIR / "data" / "mailsentinel.db",
    )
)


# ============================================================
# Database connection
# ============================================================

def get_connection() -> sqlite3.Connection:
    """
    Create a connection to the MailSentinel database.
    """

    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# Database initialization
# ============================================================

def initialize_database() -> None:
    """
    Create the MailSentinel database tables if they
    do not already exist.
    """

    with get_connection() as connection:

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS email_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                original_filename TEXT NOT NULL,

                sha256 TEXT,

                sender TEXT,

                subject TEXT,

                risk_score INTEGER NOT NULL DEFAULT 0,

                classification TEXT NOT NULL,

                recommended_action TEXT,

                security_override INTEGER NOT NULL DEFAULT 0,

                ai_threat_level TEXT,

                ai_malicious INTEGER,

                ai_confidence TEXT,

                ai_summary TEXT,

                quarantine_status TEXT,

                quarantine_id TEXT,

                quarantine_path TEXT,

                created_at TEXT NOT NULL
            )
            """
        )

        # --------------------------------------------------------
        # Database migration
        # --------------------------------------------------------

        columns = connection.execute(
            "PRAGMA table_info(email_analysis)"
        ).fetchall()

        column_names = {
            row["name"]
            for row in columns
        }

        if "analysis_json" not in column_names:
            connection.execute(
                """
                ALTER TABLE email_analysis
                ADD COLUMN analysis_json TEXT
                """
            )

        connection.commit()
        

      


# ============================================================
# Save analysis
# ============================================================

def save_analysis(
    analysis: dict[str, Any],
) -> int:
    """
    Save a completed MailSentinel analysis.

    Returns:
        Database ID of the inserted record.
    """

    initialize_database()

    email = analysis.get(
        "email",
        {},
    )

    parser = analysis.get(
        "parser",
        {},
    )

    headers = parser.get(
        "headers",
        {},
    )

    risk = analysis.get(
        "risk",
        {},
    )

    ai = analysis.get(
        "ai_analysis",
        {},
    )

    quarantine = analysis.get(
        "quarantine",
        {},
    )

    sender = headers.get(
        "from",
        "",
    )

    subject = headers.get(
        "subject",
        "",
    )

    sha256 = None

    attachments = (
        analysis
        .get("analyzers", {})
        .get("attachment_analyzer", {})
        .get("attachments", [])
    )

    if isinstance(attachments, list):
        for attachment in attachments:
            if isinstance(attachment, dict):
                attachment_hash = attachment.get(
                    "sha256"
                )

                if attachment_hash:
                    sha256 = str(
                        attachment_hash
                    )
                    break

    quarantine_status = quarantine.get(
        "status"
    )

    quarantine_id = quarantine.get(
        "quarantine_id"
    )

    quarantine_path = quarantine.get(
        "quarantine_path"
    )

    ai_malicious = ai.get(
        "is_malicious"
    )

    if isinstance(
        ai_malicious,
        bool,
    ):
        ai_malicious = int(
            ai_malicious
        )
    else:
        ai_malicious = None

    created_at = (
        quarantine.get("timestamp")
        or analysis.get("timestamp")
    )

    if not created_at:
        from datetime import datetime, timezone

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

    with get_connection() as connection:

        analysis_json = json.dumps(
        analysis,
        ensure_ascii=False,
    )

        cursor = connection.execute(
            """
            INSERT INTO email_analysis (
    original_filename,
    sha256,
    sender,
    subject,
    risk_score,
    classification,
    recommended_action,
    security_override,
    ai_threat_level,
    ai_malicious,
    ai_confidence,
    ai_summary,
    quarantine_status,
    quarantine_id,
    quarantine_path,
    created_at,
    analysis_json
)
VALUES (
    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
)
            
            """,
            (
                email.get(
                    "file",
                    "Unknown",
                ),

                sha256,

                sender,

                subject,

                int(
                    risk.get(
                        "score",
                        0,
                    )
                    or 0
                ),

                risk.get(
                    "classification",
                    "unknown",
                ),

                risk.get(
                    "recommended_action",
                    "unknown",
                ),

                int(
                    bool(
                        risk.get(
                            "security_override",
                            False,
                        )
                    )
                ),

                ai.get(
                    "threat_level"
                ),

                ai_malicious,

                ai.get(
                    "confidence"
                ),

                ai.get(
                    "summary"
                ),

                quarantine_status,

                quarantine_id,

                quarantine_path,

                created_at,

                analysis_json,
            ),
        )

        connection.commit()

        return int(
            cursor.lastrowid
        )


# ============================================================
# Retrieve analysis history
# ============================================================

def get_analysis_history(
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Return recent email analysis records.
    """

    initialize_database()

    limit = max(
        1,
        min(
            int(limit),
            500,
        ),
    )

    with get_connection() as connection:

        rows = connection.execute(
            """
            SELECT *
            FROM email_analysis
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [
        dict(row)
        for row in rows
    ]


# ============================================================
# Retrieve one analysis
# ============================================================
def get_analysis(
    analysis_id: int,
) -> dict[str, Any] | None:
    """
    Retrieve one complete analysis by database ID.
    """

    initialize_database()

    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT *
            FROM email_analysis
            WHERE id = ?
            """,
            (analysis_id,),
        ).fetchone()

    if row is None:
        return None

    record = dict(row)

    analysis_json = record.get("analysis_json")

    if analysis_json:
        try:
            analysis = json.loads(analysis_json)

            if isinstance(analysis, dict):
                analysis["analysis_id"] = record["id"]
                return analysis

        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    # Fallback for old records that don't have complete JSON.
    return record
