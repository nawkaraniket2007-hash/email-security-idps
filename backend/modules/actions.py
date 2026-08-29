from __future__ import annotations

import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parents[2]
QUARANTINE_DIR = BASE_DIR / "quarantine"


def quarantine_email(
    source_path: str | Path,
    original_filename: str,
    reason: str,
    risk_score: int | float,
) -> dict[str, Any]:
    """
    Move a malicious email into the MailSentinel quarantine directory.
    """

    source = Path(source_path)

    if not source.exists():
        raise FileNotFoundError(
            f"Email file not found: {source}"
        )

    QUARANTINE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    quarantine_id = str(uuid.uuid4())

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    safe_filename = Path(
        original_filename
    ).name

    destination_name = (
        f"{timestamp}_{quarantine_id}_{safe_filename}"
    )

    destination = QUARANTINE_DIR / destination_name

    shutil.move(
        str(source),
        str(destination),
    )

    return {
        "status": "quarantined",
        "quarantine_id": quarantine_id,
        "original_filename": safe_filename,
        "quarantine_path": str(destination),
        "reason": reason,
        "risk_score": risk_score,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }
