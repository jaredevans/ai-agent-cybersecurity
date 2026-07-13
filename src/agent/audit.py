"""Append-only JSONL audit log of every command the agent attempts."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def make_audit_logger(
    path: Path, now: Callable[[], datetime] = _utc_now
) -> Callable[[dict], dict]:
    """Return a logger that appends one JSON record per call.

    Each record is written as a single line with a leading UTC `ts` field.
    `now` is injectable for deterministic tests.
    """

    def log(record: dict) -> dict:
        entry = {"ts": now().isoformat(), **record}
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    return log
