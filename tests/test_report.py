from datetime import date
from pathlib import Path

from agent.report import report_path


def test_report_path_format(tmp_path):
    p = report_path(tmp_path, "ia", date(2026, 7, 10))
    assert p == tmp_path / "ia-2026-07-10.md"


def test_report_path_sanitizes_host(tmp_path):
    p = report_path(tmp_path, "../../etc/pwn", date(2026, 7, 10))
    # No path traversal: result stays directly inside reports_dir.
    assert p.parent == tmp_path
    assert ".." not in p.name
    assert "/" not in p.name
