"""The ssh_run tool: guard a command, then execute it read-only over SSH."""

from __future__ import annotations

import functools
import shlex
import subprocess

from claude_agent_sdk import tool

from agent.guard import check_command
from agent.redact import redact


# Reuse one SSH connection across a scan's many commands: the first command
# opens a master, the rest ride it, and it self-closes 60s after the last use.
# %C is a hash of (host, port, user), so distinct targets get distinct sockets.
_SSH_MUX_ARGS = [
    "-o", "ControlMaster=auto",
    "-o", "ControlPath=~/.ssh/.claude-agent-%C",
    "-o", "ControlPersist=60s",
]


def run_ssh(host: str, pipeline: list, *, timeout: int = 30,
            runner=subprocess.run) -> dict:
    """Execute a pre-validated pipeline on `host` over SSH.

    `pipeline` is a list of stages, each a token list, rendered as
    `stage1 | stage2 | ...` with every token shell-quoted. A flat token list
    (single command) is also accepted and treated as a one-stage pipeline.
    Connections are multiplexed (see `_SSH_MUX_ARGS`) to avoid a fresh
    handshake per command.
    """
    stages = pipeline
    if stages and not isinstance(stages[0], list):
        stages = [stages]  # a flat argv -> single-stage pipeline
    remote_cmd = " | ".join(
        " ".join(shlex.quote(tok) for tok in seg) for seg in stages)
    completed = runner(
        ["ssh", *_SSH_MUX_ARGS, host, remote_cmd],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "exit_code": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def _text(text: str, *, is_error: bool = False) -> dict:
    result = {"content": [{"type": "text", "text": text}]}
    if is_error:
        result["is_error"] = True
    return result


def _audit(audit, host, command, **fields) -> None:
    if audit is not None:
        audit({"host": host, "command": command, **fields})


async def handle_ssh_run(host: str, command: str, *,
                         runner=subprocess.run, check=check_command,
                         audit=None) -> dict:
    """Guard `command`, then run it over SSH. Returns an SDK tool result.

    Every attempt is recorded via `audit` (if provided): a rejected command is
    logged as blocked and NEVER reaches SSH; an executed command is logged with
    its exit code; a transport error is logged as allowed-but-not-executed.
    `check`, `runner`, and `audit` are injectable for tests.
    """
    verdict = check(command)
    if not verdict.allowed:
        _audit(audit, host, command, decision="blocked",
               severity=verdict.severity, reason=verdict.reason,
               executed=False, exit_code=None)
        return _text(
            f"REJECTED (read-only guard): {verdict.reason}. "
            f"Try a read-only command instead.",
            is_error=True,
        )
    try:
        result = run_ssh(host, verdict.pipeline or [verdict.argv],
                         runner=runner)
    except subprocess.TimeoutExpired:
        _audit(audit, host, command, decision="allowed", severity="",
               reason="", executed=False, exit_code=None, error="timeout")
        return _text("SSH command timed out.", is_error=True)
    except Exception as exc:  # noqa: BLE001 - surface transport errors
        _audit(audit, host, command, decision="allowed", severity="",
               reason="", executed=False, exit_code=None, error=str(exc))
        return _text(f"SSH error: {exc}", is_error=True)

    _audit(audit, host, command, decision="allowed", severity="", reason="",
           executed=True, exit_code=result["exit_code"])
    # Redact secrets before the output reaches the model (and thus the API and
    # the report). The audit log stores no command output, so nothing to redact
    # there.
    text = (f"exit_code: {result['exit_code']}\n"
            f"--- stdout ---\n{redact(result['stdout'])}\n"
            f"--- stderr ---\n{redact(result['stderr'])}")
    return _text(text)


def make_ssh_run(host: str, audit=None, self_hosts=frozenset()):
    """Build the ssh_run SDK tool bound to a target host (and optional audit).

    `self_hosts` widens curl's allowed targets to the host's own IPs/hostnames
    (on top of loopback); it is bound into the guard for this tool.
    """
    check = functools.partial(check_command, self_hosts=self_hosts)

    @tool(
        "ssh_run",
        "Run a single read-only command on the target host over SSH and "
        "return its stdout, stderr, and exit code. Only read-only commands "
        "are permitted; write/modify commands are rejected.",
        {"command": str},
    )
    async def ssh_run(args):
        return await handle_ssh_run(host, args["command"], audit=audit,
                                    check=check)

    return ssh_run
