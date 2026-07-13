"""Phase 1: deterministic baseline collection.

Runs each checklist command through the read-only guard and, if allowed, over
SSH — capturing output. No LLM involved, so coverage is identical every run and
the logic is fully unit-testable with an injected runner.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from agent.guard import check_command
from agent.ssh_tool import run_ssh


@dataclass(frozen=True)
class CollectionResult:
    category: str
    command: str
    allowed: bool
    exit_code: int | None
    stdout: str
    stderr: str


def collect_baseline(host: str, checklist: dict[str, list[str]], *,
                     runner=subprocess.run, check=check_command,
                     audit=None, timeout: int = 120) -> list["CollectionResult"]:
    """Run every checklist command (in order), returning a CollectionResult each.

    Rejected commands are recorded and skipped (never sent to SSH). Every
    attempt is written to `audit` when provided.
    """
    results: list[CollectionResult] = []
    for category, commands in checklist.items():
        for command in commands:
            verdict = check(command)
            if not verdict.allowed:
                if audit is not None:
                    audit({"host": host, "command": command,
                           "category": category, "decision": "blocked",
                           "severity": verdict.severity,
                           "reason": verdict.reason, "executed": False,
                           "exit_code": None})
                results.append(CollectionResult(
                    category, command, False, None, "", verdict.reason))
                continue

            error = None
            try:
                r = run_ssh(host, verdict.pipeline or [verdict.argv],
                            timeout=timeout, runner=runner)
                exit_code, stdout, stderr = (
                    r["exit_code"], r["stdout"], r["stderr"])
            except Exception as exc:  # noqa: BLE001 - surface transport errors
                exit_code, stdout, stderr = None, "", f"ERROR: {exc}"
                error = str(exc)

            if audit is not None:
                record = {"host": host, "command": command,
                          "category": category, "decision": "allowed",
                          "severity": "", "reason": "",
                          "executed": exit_code is not None,
                          "exit_code": exit_code}
                if error is not None:
                    record["error"] = error
                audit(record)
            results.append(CollectionResult(
                category, command, True, exit_code, stdout, stderr))
    return results
