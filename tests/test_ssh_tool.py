import asyncio
import subprocess

import agent.ssh_tool as ssh_tool
from agent.guard import GuardResult


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --- run_ssh: command construction ---------------------------------------

def test_run_ssh_builds_quoted_remote_command_and_parses_result():
    captured = {}

    def fake_runner(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return FakeCompleted(0, "Ubuntu 24.04.4 LTS\n", "")

    result = ssh_tool.run_ssh("ia", ["cat", "/etc/os-release"],
                              runner=fake_runner)

    assert result["exit_code"] == 0
    assert "Ubuntu 24.04.4 LTS" in result["stdout"]
    assert captured["cmd"][0] == "ssh"
    # host and remote command are the last two argv elements (mux -o args first)
    assert captured["cmd"][-2] == "ia"
    assert captured["cmd"][-1] == "cat /etc/os-release"
    # connection multiplexing is enabled
    assert "ControlMaster=auto" in captured["cmd"]
    # forwards the flags run_ssh relies on
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True


def test_run_ssh_quotes_tokens_with_spaces():
    captured = {}

    def fake_runner(cmd, **kwargs):
        captured["cmd"] = cmd
        return FakeCompleted(0, "", "")

    ssh_tool.run_ssh("ia", ["find", "/etc", "-name", "a b"],
                     runner=fake_runner)
    assert "'a b'" in captured["cmd"][-1]


# --- handle_ssh_run: the guard integration (the safety invariant) --------

def test_rejected_command_never_reaches_ssh():
    calls = []

    def fake_runner(cmd, **kwargs):
        calls.append(cmd)
        raise AssertionError("runner must not run for a rejected command")

    def deny(command):
        return GuardResult(allowed=False, reason="not allowed",
                           argv=[], severity="write")

    result = asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "rm -rf /", runner=fake_runner, check=deny))

    assert result.get("is_error") is True
    assert "REJECTED" in result["content"][0]["text"]
    assert calls == []  # SSH was never invoked


def test_allowed_command_runs_ssh_and_formats_result():
    def allow(command):
        return GuardResult(allowed=True, reason="",
                           argv=["cat", "/etc/os-release"], severity="")

    def fake_runner(cmd, **kwargs):
        assert cmd[0] == "ssh"
        assert cmd[-2] == "ia"
        assert cmd[-1] == "cat /etc/os-release"
        return FakeCompleted(0, "Ubuntu 24.04\n", "")

    result = asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "cat /etc/os-release", runner=fake_runner, check=allow))

    assert result.get("is_error") is None
    assert "exit_code: 0" in result["content"][0]["text"]
    assert "Ubuntu 24.04" in result["content"][0]["text"]


def test_ssh_timeout_is_reported_as_error():
    def allow(command):
        return GuardResult(allowed=True, reason="",
                           argv=["uname", "-a"], severity="")

    def fake_runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 30)

    result = asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "uname -a", runner=fake_runner, check=allow))

    assert result.get("is_error") is True
    assert "timed out" in result["content"][0]["text"]


# --- handle_ssh_run: audit records --------------------------------------

def test_audit_records_rejected_attempt():
    records = []

    def deny(command):
        return GuardResult(allowed=False, reason="nope", argv=[],
                           severity="write")

    def fake_runner(cmd, **kwargs):
        raise AssertionError("runner must not run for a rejected command")

    asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "touch /tmp/x", runner=fake_runner, check=deny,
        audit=records.append))

    assert len(records) == 1
    assert records[0]["command"] == "touch /tmp/x"
    assert records[0]["decision"] == "blocked"
    assert records[0]["executed"] is False


def test_audit_records_executed_attempt():
    records = []

    def allow(command):
        return GuardResult(allowed=True, reason="", argv=["uname", "-a"],
                           severity="")

    def fake_runner(cmd, **kwargs):
        return FakeCompleted(0, "Linux\n", "")

    asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "uname -a", runner=fake_runner, check=allow,
        audit=records.append))

    assert len(records) == 1
    assert records[0]["decision"] == "allowed"
    assert records[0]["executed"] is True
    assert records[0]["exit_code"] == 0


def test_audit_records_timeout_attempt():
    records = []

    def allow(command):
        return GuardResult(allowed=True, reason="", argv=["uname", "-a"],
                           severity="")

    def fake_runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 30)

    result = asyncio.run(ssh_tool.handle_ssh_run(
        "ia", "uname -a", runner=fake_runner, check=allow,
        audit=records.append))

    assert result.get("is_error") is True
    assert len(records) == 1
    assert records[0]["decision"] == "allowed"
    assert records[0]["executed"] is False
    assert records[0]["error"] == "timeout"
