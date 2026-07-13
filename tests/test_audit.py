import json
from datetime import date, datetime, timezone

from agent.audit import make_audit_logger
from agent.report import audit_path


def test_audit_logger_appends_jsonl_with_timestamp(tmp_path):
    fixed = datetime(2026, 7, 10, 14, 3, 22, tzinfo=timezone.utc)
    log = make_audit_logger(tmp_path / "a.jsonl", now=lambda: fixed)

    log({"host": "ia", "command": "cat /etc/os-release",
         "decision": "allowed", "severity": "", "reason": "",
         "executed": True, "exit_code": 0})
    log({"host": "ia", "command": "rm -rf /", "decision": "blocked",
         "severity": "catastrophic", "reason": "CATASTROPHIC: ...",
         "executed": False, "exit_code": None})

    lines = (tmp_path / "a.jsonl").read_text().strip().split("\n")
    assert len(lines) == 2

    r0 = json.loads(lines[0])
    assert r0["ts"] == "2026-07-10T14:03:22+00:00"
    assert r0["command"] == "cat /etc/os-release"
    assert r0["decision"] == "allowed"
    assert r0["executed"] is True
    assert r0["exit_code"] == 0

    r1 = json.loads(lines[1])
    assert r1["decision"] == "blocked"
    assert r1["severity"] == "catastrophic"
    assert r1["executed"] is False


def test_audit_path_format(tmp_path):
    p = audit_path(tmp_path, "ialocal", date(2026, 7, 10))
    assert p == tmp_path / "ialocal-2026-07-10-audit.jsonl"


def test_audit_path_sanitizes_host(tmp_path):
    p = audit_path(tmp_path, "../../etc/pwn", date(2026, 7, 10))
    assert p.parent == tmp_path
    assert ".." not in p.name
    assert "/" not in p.name
