# AI Cybersecurity Agent

A Claude-driven agent that SSHes into an Ubuntu host as root, performs a
read-only **security-posture assessment** (system & kernel; users, auth &
access; network & firewall; packages, services & persistence) using
**code-enforced read-only** commands, and writes a local markdown report plus
an append-only audit log of every command it attempts.

## How it works

A run has two phases: a deterministic baseline sweep, then an agentic loop where
the model runs follow-up commands (each gated by the read-only guard) until it
has enough evidence to write the report. See [`HOW-IT-WORKS.md`](HOW-IT-WORKS.md)
for the full walkthrough.

![Execution workflow: deterministic baseline, then an agentic guard-gated tool loop, then the report. Command output is redacted for secrets before it reaches the model, and every attempted command — executed or rejected, in both phases — is appended to the audit log.](workflow.svg)

## Repository

```bash
git clone git@github.com:jaredevans/ai-agent-cybersecurity.git
cd ai-agent-cybersecurity
```

## Requirements

- [uv](https://docs.astral.sh/uv/)
- An SSH host reachable by alias (key auth already configured)
- Claude authentication — see below

## Authentication

By default the agent uses your existing **Claude Code login** (the Agent SDK
reuses it) — no API key needed. For headless use (cron, CI, a server), you can
instead supply an Anthropic API key: copy `.env.example` to `.env` and set
`ANTHROPIC_API_KEY`. `.env` is gitignored and only loaded if present, so with no
`.env` the login is used. An already-set `ANTHROPIC_API_KEY` env var is never
overridden. Never commit a real key; rotate any key that leaks.

## Usage

```bash
uv sync
uv run agent <host>      # e.g. uv run agent ia
```

Outputs, both under `reports/`:

- `reports/<host>-<YYYY-MM-DD>.md` — the human-readable report.
- `reports/<host>-<YYYY-MM-DD>-audit.jsonl` — one JSON record per attempted
  command: UTC timestamp, the command, the guard decision and severity, whether
  it executed on the server, and its exit code.

## Safety model

The agent connects as root but can only run read-only commands. This is
**trust but verify**: the system prompt instructs the agent to stay strictly
read-only and we expect it to comply — but we do not rely on that alone.
Enforcement also lives in code (`src/agent/guard.py`), so the boundary holds
regardless of how the model behaves. Every command passes through
`check_command`, which returns one of three outcomes:

- **Catastrophic — always blocked (tripwire).** An irreversible-damage denylist
  (`rm -rf`, `mkfs`, `dd` to a device, `shutdown`/`reboot`, `fdisk`/`parted`,
  `userdel`, fork bombs, redirection onto a block device, recursive `chmod`/
  `chown` on system paths, …) is checked **first**, so it cannot be overridden
  even by a mistaken allowlist entry. Recorded with severity `catastrophic`.
- **Allowed — read-only.** Either a **Tier 1** binary (e.g. `cat`, `uname`,
  `lsb_release`) that is inherently read-only with any arguments, or a **Tier 2**
  dual-use binary (e.g. `ip`, `systemctl`, `find`, `dpkg`, `ss`) invoked in an
  explicitly allowlisted read form. Tier 2 rules allowlist read subcommands
  rather than blocklisting writes. **Network and database clients** are
  supported in a locked-down read-only form so the agent can probe local
  service posture (e.g. whether Redis or PostgreSQL requires auth) with **no
  egress and no write capability** — all are pinned to a **loopback target**
  through one shared egress check:
  - `curl` — local `http`/`https` probes only (no file writes, no uploads).
  - `redis-cli` — `PING`, `INFO`, `CONFIG GET`, `CLIENT LIST` only.
  - `psql` — `--version` and `-l`/`--list` (database listing + auth probe).
  - `mysql` — `--version` only (running SQL is a file-write/RCE surface).
- **Blocked — reversible write.** Anything else (deny-by-default), including
  shell metacharacters, path-as-binary, and `su`/`doas`/`runuser`/`pkexec`.
  `sudo` is allowed **only** as a bare wrapper around a read-only command
  (`sudo cat /etc/shadow`, run as `sudo -n …`); sudo flags, env assignments,
  and nested `sudo` are blocked. Recorded with severity `write`.

Importantly, the agent is **not** told the exact list of allowed commands in advance. This is an intentional design choice: by letting the agent determine the best commands to run for its investigation, it will occasionally attempt to run safe commands that are not yet on the allowlist. These rejected commands act as a natural pressure test and are explicitly documented by the agent in its final report (the "Agent Feedback" loop), allowing developers to continuously discover and add useful read-only tools to the allowlist over time.

### The agent's only two tools are custom MCP tools

`ssh_run` and `write_report` are **not** built-in Claude Code tools. They are
custom tools this app defines and serves from an **in-process MCP server**
(`create_sdk_mcp_server(name="recon", …)` in `src/agent/main.py`), so the model
calls them under the `mcp__recon__` namespace: `mcp__recon__ssh_run` and
`mcp__recon__write_report`. `ssh_run` runs a command through `check_command` and,
only if allowed, over SSH; `write_report` writes to one fixed local path.

This separation is the whole point, and it is what lets us lock the agent down
without disarming it. The SDK draws tools from two independent places: the
**built-in** toolset (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, …) and any
**MCP servers** you register. `build_options` sets `tools=[]`, which clears the
built-in toolset **but leaves the MCP tools untouched**. So the agent loses the
dangerous, unguarded capabilities — critically the built-in `Bash`, which runs on
the operator's machine and could reach the target directly (`ssh <host>
'<anything>'`), an unguarded route straight around the read-only guard — while
keeping everything it actually needs: guarded remote execution via
`mcp__recon__ssh_run` and report-writing via `mcp__recon__write_report`. In other
words, the agent can still do its job with built-ins disabled precisely *because*
its real capabilities live in the MCP server, not in `Bash`.

The system prompt already tells the agent to use only these two tools — but,
again, trust but verify: two independent layers enforce it in code so a
misbehaving or prompt-injected model cannot reach for anything else:

1. **`tools=[]`** removes every built-in tool from the model's toolset.
2. **A PreToolUse hook** (`deny_non_recon_tools`) denies any tool call that is
   not one of the two `mcp__recon__` tools — a backstop so that if layer 1 ever
   regressed, a `Bash`/`Read`/`Write` call is still refused before it runs. (We
   use a hook rather than the SDK's `can_use_tool` callback because `allowed_tools`
   and settings-file allow rules shadow that callback; a PreToolUse hook gates
   every call.)

`tests/test_main_options.py` asserts `tools == []`, that the allowlist contains
only the two `mcp__recon__` tools, and that the hook denies built-ins — so none
of this can be reopened silently.

### Secret redaction

Read-only still means the agent reads sensitive files **as root** (`/etc/shadow`,
private keys, `docker inspect` output, `.env` files, database config). To keep
that material out of the model's context (and the Anthropic API) and out of the
written report, **all command output is passed through `redact()`
(`src/agent/redact.py`) before it reaches the model** — both `ssh_run` results
and the Phase-1 baseline. Redaction is high-precision (it targets specific secret
shapes, so it does not mangle security-relevant non-secrets like
`PasswordAuthentication yes`). It masks private keys, `/etc/shadow` hashes, Redis
`requirepass`, `NAME=VALUE` secret env vars (`.env` / `docker inspect` / compose /
systemd / `my.cnf`, e.g. `POSTGRES_PASSWORD`), credentials in URLs
(`DATABASE_URL`), and `.pgpass` password fields — keeping each value's first and
last two characters (`AKIA...9f`), or fully masking anything ≤ 8 chars. It is
best-effort and pattern-based, and unit-tested in `tests/test_redact.py`. The
audit log records only the command and its decision, never output.

## Tests

Because enforcement lives in code, the guard and its supporting modules are
covered by a `pytest` suite (`tests/`). Run it with:

```bash
uv run pytest
```
