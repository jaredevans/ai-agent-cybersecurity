"""CLI entry point: run the read-only recon agent against a target host."""

from __future__ import annotations

import argparse
import asyncio
from datetime import date
from pathlib import Path

from claude_agent_sdk import (
    ClaudeAgentOptions,
    HookMatcher,
    create_sdk_mcp_server,
    query,
)

from agent.audit import make_audit_logger
from agent.checklist import CHECKLIST
from agent.collect import collect_baseline
from agent.config import load_env_file
from agent.identity import discover_self_hosts
from agent.prompts import SYSTEM_PROMPT, build_initial_prompt
from agent.report import audit_path, make_write_report, report_path
from agent.ssh_tool import make_ssh_run

REPORTS_DIR = Path("reports")
ENV_FILE = Path(".env")

# The only two tools the agent may use. Both are provided by our in-process
# "recon" MCP server; ssh_run is guard-gated and write_report is path-confined.
ALLOWED_TOOLS = ["mcp__recon__ssh_run", "mcp__recon__write_report"]


async def deny_non_recon_tools(input_data, tool_use_id, context):
    """PreToolUse hook: allow ONLY the two recon tools; deny everything else.

    This is a second, independent layer behind `tools=[]`. We use a PreToolUse
    hook rather than a `can_use_tool` callback because the SDK auto-approves any
    tool in `allowed_tools` (and honours settings-file allow rules) BEFORE the
    callback — so `can_use_tool` is shadowed and never consulted for those, and
    it emits CanUseToolShadowedWarning. A PreToolUse hook is the SDK's
    documented way to "gate every tool call": it runs for every tool and a
    `deny` decision blocks execution. So even if a future change re-enabled
    built-in tools, a `Bash`/`Read`/`Write`/`WebFetch` call is refused here
    before it runs.
    """
    tool_name = input_data.get("tool_name", "")
    if tool_name in ALLOWED_TOOLS:
        return {}
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"tool '{tool_name}' is not permitted; this agent may use only "
                "the read-only recon tools ssh_run and write_report"),
        }
    }


def build_options(server) -> ClaudeAgentOptions:
    """SDK options that confine the agent to exactly the two recon tools.

    Two independent layers enforce this in code (not via the prompt):

    1. `tools=[]` disables ALL built-in tools (Bash, Read, Write, Edit,
       WebFetch, ...). Without it the SDK loads the full Claude Code toolset;
       the local `Bash` tool alone can reach the target (`ssh <host>
       '<anything>'`), an unguarded route around the read-only guard.
    2. A PreToolUse hook (`deny_non_recon_tools`) denies any non-recon tool call
       as a backstop, so layer 1 regressing does not silently reopen that route.

    `allowed_tools` auto-approves the two recon tools so they run without a
    prompt; the hook still runs for them (and allows them).
    """
    return ClaudeAgentOptions(
        model="claude-sonnet-5",
        system_prompt=SYSTEM_PROMPT,
        mcp_servers={"recon": server},
        tools=[],
        allowed_tools=ALLOWED_TOOLS,
        hooks={"PreToolUse": [HookMatcher(hooks=[deny_non_recon_tools])]},
        permission_mode="default",
    )


async def run_agent(host: str) -> Path:
    today = date.today()
    audit = make_audit_logger(audit_path(REPORTS_DIR, host, today))

    # Phase 1: deterministic baseline collection (through the guard + audit).
    print(f"Collecting baseline from '{host}' ...")
    baseline = collect_baseline(host, CHECKLIST, audit=audit)
    ran = sum(1 for r in baseline if r.allowed)
    print(f"Baseline: {ran}/{len(baseline)} commands executed.")

    # Identity: widen curl's allowed targets to this host's own IPs/hostnames.
    self_hosts = discover_self_hosts(host)
    if self_hosts:
        print(f"Self-target hosts for curl: {', '.join(sorted(self_hosts))}")

    # Phase 2: agentic analysis + findings report.
    ssh_run = make_ssh_run(host, audit=audit, self_hosts=self_hosts)
    write_report = make_write_report(host, today, REPORTS_DIR)
    server = create_sdk_mcp_server(
        name="recon", version="0.1.0", tools=[ssh_run, write_report]
    )
    options = build_options(server)

    async for message in query(
        prompt=build_initial_prompt(host, baseline),
        options=options,
    ):
        print(message)

    print(f"\nAudit log: {audit_path(REPORTS_DIR, host, today)}")
    return report_path(REPORTS_DIR, host, today)


def cli() -> None:
    parser = argparse.ArgumentParser(
        description="Read-only AI security recon agent (POC).")
    parser.add_argument("host", help="Target SSH host (e.g. an ssh_config alias).")
    args = parser.parse_args()

    # Opt-in: if a local .env sets ANTHROPIC_API_KEY, use it; otherwise the
    # agent falls back to the existing Claude Code login. Never overrides an
    # already-set environment variable.
    load_env_file(ENV_FILE)

    path = asyncio.run(run_agent(args.host))
    print(f"Report saved to: {path}")


if __name__ == "__main__":
    cli()
