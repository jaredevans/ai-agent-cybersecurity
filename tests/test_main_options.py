"""The agent must be confined to exactly the two recon tools.

This is the code-level guarantee behind the safety model: `tools=[]` disables
every built-in tool (Bash, Read, Write, Edit, WebFetch, ...), so the only way to
reach the target host is the guard-gated ssh_run, and the only way to touch disk
is the path-confined write_report. If a future change drops `tools=[]` (or the
SDK reverts to loading the full toolset), the agent regains an unguarded
`Bash` -> `ssh <host>` route around the read-only guard — so we assert on it.
"""

import asyncio

from claude_agent_sdk import create_sdk_mcp_server, tool

from agent.main import ALLOWED_TOOLS, build_options, deny_non_recon_tools


@tool("ssh_run", "stub", {"command": str})
async def _ssh_run(args):  # pragma: no cover - never invoked in this test
    return {"content": [{"type": "text", "text": ""}]}


@tool("write_report", "stub", {"content": str})
async def _write_report(args):  # pragma: no cover - never invoked
    return {"content": [{"type": "text", "text": ""}]}


def _server():
    return create_sdk_mcp_server(
        name="recon", version="0.1.0", tools=[_ssh_run, _write_report])


def test_all_builtin_tools_are_disabled():
    # tools=[] means the SDK loads NO built-in tools (no Bash/Read/Write/...).
    opts = build_options(_server())
    assert opts.tools == []


def test_only_the_two_recon_tools_are_allowed():
    opts = build_options(_server())
    assert set(opts.allowed_tools) == {
        "mcp__recon__ssh_run", "mcp__recon__write_report"}
    assert set(ALLOWED_TOOLS) == set(opts.allowed_tools)


def test_no_builtin_tool_ever_appears_in_the_allowlist():
    # Guards against someone "fixing" a prompt by pre-approving Bash/Read/etc.
    opts = build_options(_server())
    for name in opts.allowed_tools:
        assert name.startswith("mcp__recon__"), name


# --- layer 2: the PreToolUse deny-hook -------------------------------------
def test_pretooluse_hook_is_registered():
    opts = build_options(_server())
    assert "PreToolUse" in opts.hooks
    assert opts.hooks["PreToolUse"], "expected at least one PreToolUse matcher"


def test_hook_allows_the_recon_tools():
    for name in ALLOWED_TOOLS:
        out = asyncio.run(deny_non_recon_tools({"tool_name": name}, "id", None))
        assert out == {}  # {} == allow


def test_hook_denies_builtin_tools():
    for name in ["Bash", "Read", "Write", "Edit", "WebFetch", "Glob"]:
        out = asyncio.run(deny_non_recon_tools({"tool_name": name}, "id", None))
        decision = out["hookSpecificOutput"]["permissionDecision"]
        assert decision == "deny", (name, out)


def test_hook_denies_unknown_or_empty_tool():
    out = asyncio.run(deny_non_recon_tools({"tool_name": ""}, "id", None))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
