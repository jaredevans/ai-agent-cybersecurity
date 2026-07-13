"""The write_report tool: write the markdown report to one confined path."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

from claude_agent_sdk import tool

_SAFE = re.compile(r"[^A-Za-z0-9_-]")


def report_path(reports_dir: Path, host: str, today: date) -> Path:
    safe_host = _SAFE.sub("_", host)
    return reports_dir / f"{safe_host}-{today.isoformat()}.md"


def audit_path(reports_dir: Path, host: str, today: date) -> Path:
    safe_host = _SAFE.sub("_", host)
    return reports_dir / f"{safe_host}-{today.isoformat()}-audit.jsonl"


def make_write_report(host: str, today: date, reports_dir: Path):
    """Build the write_report SDK tool bound to a single output path."""
    target = report_path(reports_dir, host, today)

    @tool(
        "write_report",
        "Write the final markdown security report. Provide the full markdown "
        "document as `content`; it is saved to a fixed local path.",
        {"content": str},
    )
    async def write_report(args):
        reports_dir.mkdir(parents=True, exist_ok=True)
        target.write_text(args["content"], encoding="utf-8")
        return {"content": [{"type": "text",
                             "text": f"Report written to {target}"}]}

    return write_report
