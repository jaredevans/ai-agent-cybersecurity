# How It Works

This document explains how the AI Security Agent authenticates with Anthropic, and details the robust safety model used to evaluate and restrict commands executed by the agent.

## Claude Code Login and Authentication

The agent leverages the `claude_agent_sdk` to interface with Anthropic's Claude models. By default, the SDK automatically utilizes the existing **Claude Code login** for authentication.

Here is how the authentication flow works:
1. **Environment Variables Check**: The agent first checks for an `.env` file (via `agent.config.load_env_file()`) or existing system environment variables to see if an `ANTHROPIC_API_KEY` is explicitly provided.
2. **Claude Code Fallback**: If no API key is specified in the environment, the `claude_agent_sdk` seamlessly falls back to using the authenticated session managed by the local `claude` CLI tool (Claude Code).
3. **Opt-in Overrides**: Existing environment variables are never overwritten. This allows operators to easily switch to a specific API key via a local `.env` file without hardcoding secrets, while maintaining a frictionless out-of-the-box experience relying on their active Claude Code session.

## Workflow

Running `uv run agent <host>` (`agent.main.run_agent`) executes the assessment in two phases.

### Phase 1 — Deterministic baseline (no LLM)

Before collection, `detect_privilege()` (`agent/privilege.py`) probes the connecting user with two fixed read-only commands — `id -u`, then (if not root) `sudo -n id -u`. If the user is non-root but passwordless sudo escalates to root, every baseline command is prefixed with `sudo` (which the guard rewrites to `sudo -n …`); as root, commands run bare. On a host with `Defaults requiretty` the `sudo -n` probe fails without a TTY, so the agent falls back to unprivileged reads.

`collect_baseline()` (`agent/collect.py`) runs a fixed checklist (`agent/checklist.py` — ~40 commands across the four assessment categories) in order. Each command passes through the same read-only guard and, if allowed, is run over SSH with its output captured. Because this phase is hardcoded and LLM-free, it **guarantees a consistent floor of coverage on every run** and is fully unit-testable. Its results are formatted into the first user message for Phase 2.

### Phase 2 — Agentic analysis (Claude Agent SDK)

The baseline is handed to Claude via `claude_agent_sdk.query()` (`agent/main.py`), which drives a multi-turn tool loop. Claude is exposed exactly two tools, and both are **custom tools served by an in-process MCP server**, not built-in Claude Code tools. `agent/main.py` registers them with `create_sdk_mcp_server(name="recon", …)`, so the model calls them under the `mcp__recon__` namespace:

- `mcp__recon__ssh_run(command)` — guard-check a command and, if allowed, run it read-only over SSH, returning stdout/stderr/exit code (`agent/ssh_tool.py`).
- `mcp__recon__write_report(content)` — write the final markdown report to one fixed, confined path (`agent/report.py`).

**Why the tools being MCP tools matters.** The SDK draws tools from two independent registries: the **built-in** toolset (`Bash`, `Read`, `Write`, `Edit`, `WebFetch`, …) and any **MCP servers** you register. That independence is what lets the agent be locked down without being disarmed. The system prompt tells the agent to use only the two recon tools and we expect it to — but this is **trust but verify**: two code-level layers enforce the boundary regardless of how the model behaves:

1. `build_options` sets **`tools=[]`** on `ClaudeAgentOptions`, which clears the *built-in* toolset but leaves the MCP tools untouched. So the built-in `Bash` — which runs on the operator's machine and could reach the target directly (`ssh <host> '<anything>'`), an unguarded path around the read-only guard — is gone, while guarded remote execution (`mcp__recon__ssh_run`) and report-writing (`mcp__recon__write_report`) remain. The agent can still do everything it needs *because* its real capabilities live in the MCP server, not in `Bash`.
2. A **PreToolUse hook** (`deny_non_recon_tools`) denies any tool call that is not one of the two `mcp__recon__` tools — a backstop if layer 1 ever regressed. (A `can_use_tool` callback would not do: `allowed_tools` and settings-file allow rules shadow it; a PreToolUse hook gates every call.)

`tests/test_main_options.py` asserts `tools == []`, that only the two `mcp__recon__` tools are allowlisted, and that the hook denies built-ins — so none of this can regress unnoticed.

**The iteration loop is not written in this app; it is the SDK's tool-use loop.** Each turn is: Claude reasons over everything gathered so far → emits an `ssh_run` tool call → the guard gates it (a rejection is returned to Claude as an error, and it adapts to another read-only command) → the command's output is returned as the tool result → Claude decides the next command. The signal driving each iteration is simply the output of the previous command — e.g. a baseline `ss` line showing Redis on `127.0.0.1:6380` leads Claude to `redis-cli … CONFIG GET requirepass`, then to reading `redis.conf`, then to a finding.

### How Claude decides it has enough evidence

There is **no code-level threshold, coverage check, or iteration cap** for "enough." The stopping point is the model's own judgment, cued entirely by the prompt: the system prompt instructs it to *"Call the `write_report` tool exactly once, at the end,"* and the task message tells it to investigate anomalies and gather the evidence a finding depends on, *then* write the report. When Claude's follow-up commands stop surfacing anything new and it has evidence for every finding it intends to make, it simply stops emitting `ssh_run` calls and calls `write_report` instead. The SDK loop then terminates because Claude produces a turn with no further tool calls. This adaptive stopping is precisely why Phase 1 exists as a deterministic floor: the baseline dimensions are always covered regardless of how deep — or shallow — the model's Phase 2 exploration happens to go.

Every command in both phases, executed or rejected, is appended to `reports/<host>-<date>-audit.jsonl`.

## Safety Model

The agent employs a rigorous **read-only, pure-function guard** (implemented in `src/agent/guard.py`) to validate commands before they are sent over SSH. The guard evaluates pipeline stages individually and categorizes every proposed command into one of three distinct severity outcomes: **Allowed**, **Catastrophic (Blocked)**, or **Write (Blocked)**.

The primary control mechanism is **deny-by-default**. Commands are only executed if they belong to a curated allowlist. Furthermore, shell metacharacters (like `>`, `<`, `;`, `&`, `$`, `` ` ``) are globally blocked. Pipes (`|`) are permitted, but the pipeline is segmented, and every individual stage must independently pass the guard checks.

**`sudo` as a transparent wrapper.** `sudo <command>` is accepted only when `<command>` itself passes the read-only guard. The guard strips the leading `sudo`, validates the inner command through the *identical* Tier 1 / Tier 2 / catastrophic logic, and — on success — executes it as `sudo -n <command>` (the `-n` is injected so a host without passwordless sudo fails fast instead of hanging on a password prompt). Because the strip happens *before* the catastrophic tripwire, `sudo rm -rf /` and `sudo shutdown` still classify as catastrophic exactly like their unwrapped forms. Only the bare wrapper is allowed: sudo flags and env assignments (`-e`/sudoedit, `-i`/`-s` shells, `-E`, `-u`, `--`, `VAR=val`) and nested `sudo sudo …` are rejected. The other privilege-escalation prefixes — `su`, `doas`, `runuser`, `pkexec` — remain unconditionally blocked.

### 1. Catastrophic (Blocked)
These commands are checked **first**, acting as a strict tripwire. These are operations that can cause irreversible damage to the target system (e.g., wiping disks, destroying partitions, removing logical volumes, or recursive deletions on system paths). 
Even if a command were mistakenly added to the allowlist, the catastrophic tripwire would catch and block it.

**Examples of Catastrophic Operations Blocked:**
*   **Irreversibly destructive binaries:** `mkswap`, `wipefs`, `blkdiscard`, `shred`, `fdisk`, `sfdisk`, `cfdisk`, `sgdisk`, `parted`, `cryptsetup`, `pvremove`, `vgremove`, `lvremove`, `mdadm`, `shutdown`, `reboot`, `halt`, `poweroff`, `telinit`, `grub-install`, `userdel`, `groupdel`
*   **Filesystem creation:** `mkfs` and `mkfs.*`
*   **Destructive patterns:** Fork bombs (`:(){`, `:|:&`)
*   **Context-aware catastrophic commands:**
    *   `rm` when used with `--recursive`, `-r`, `-R`, or `--no-preserve-root`
    *   `dd` when writing to a block device (`of=/dev/...`)
    *   `kill` when signaling all processes (e.g., `kill -9 -1`)
    *   `chmod`, `chown`, `chgrp` when used recursively on system paths (`/`, `/etc`, `/bin`, etc.)
    *   `systemctl` when changing availability (`poweroff`, `reboot`, `halt`, `isolate`, etc.)
    *   `tee`, `cp`, `mv`, `ln`, `install`, `truncate` when targeting critical system files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/boot/grub/grub.cfg`, etc.)
    *   Redirection (`>`) onto block devices.

### 2. Allowed
Commands that the agent is permitted to run. The allowlist is divided into two tiers:

*   **Tier 1: Inherently Read-Only Binaries**
    These are commands that cannot write state or execute other programs, regardless of the arguments provided. They are allowed with any arguments.
    **Allowed Tier 1 Binaries:** `lsb_release`, `uname`, `uptime`, `cat`, `head`, `tail`, `stat`, `readlink`, `realpath`, `id`, `who`, `w`, `last`, `getent`, `groups`, `ps`, `df`, `du`, `lsblk`, `findmnt`, `blkid`, `ls`, `dpkg-query`, `netstat`, `lscpu`, `lsmod`, `lsof`, `printenv`, `free`, `vmstat`, `grep`, `getcap`, `aa-status`, `lastb`, `which`, `systemd-detect-virt`, `wc`, `cut`, `tr`, `egrep`, `fgrep`, `getfacl`, `lsattr`, `lslogins`, `apparmor_status`.

*   **Tier 2: Dual-Use Binaries**
    These binaries are capable of both reading and writing state. The guard applies explicit, strict rules to allowlist *only* the read subcommands or flags, rejecting any arguments that could modify the system or establish an outbound connection. The network and database clients (`curl`, `redis-cli`, `psql`) additionally route their target host through a single shared egress check (`_target_host_allowed`), so every client enforces the same loopback/self-host restriction through one audited code path rather than each reimplementing it. 
    **Allowed Tier 2 Binaries (restricted to specific read-only subcommands/flags):**
    `sort` and `uniq` (stream filters — permitted only without their file-writing forms: `sort -o`/`--output`/`--compress-program`, and `uniq`'s second positional output file, are rejected), `redis-cli` (locked to a loopback target and only the read subcommands `PING`, `INFO`, `CONFIG GET`, `CLIENT LIST`; server-side RCE/write subcommands such as `CONFIG SET`, `EVAL`, `MODULE LOAD`, `SHUTDOWN`, non-loopback `-h`/`-u`, and exec/local-write flags `--eval`/`--rdb`/`--pipe` are all rejected), `mysql` (restricted to `--version` only — running SQL is a file-write/RCE surface via `INTO OUTFILE`/`LOAD_FILE`, so no query, file, or interactive mode is permitted), `psql` (restricted to `--version` and `-l`/`--list` with loopback connection/auth flags; `-c`/`-f` queries, `-o`/`-L` file output, `\` meta-commands like `\!`/`\copy`, non-loopback `-h`, and interactive sessions are all rejected), `postconf`, `fail2ban-client`, `openssl`, `ip`, `chage`, `ss`, `lastlog`, `docker`, `hostname`, `nginx`, `apache2ctl`, `apachectl`, `pm2`, `passwd`, `ssh-keygen`, `pro`, `ubuntu-advantage`, `apt-cache`, `iptables`, `ip6tables`, `nft`, `systemctl`, `sysctl`, `ufw`, `apt`, `snap`, `journalctl`, `crontab`, `find`, `sshd`, `auditctl`, `dmesg`, `resolvectl`, `hostnamectl`, `date`, `arp`, `mount` (no arguments allowed), `dpkg`, `file`, `curl` (restricted strictly to local loopback/self-host HTTP probing, no file writes or egress permitted).

### 3. Write / General Deny (Blocked)
This category captures everything that is not explicitly allowed in Tier 1 or Tier 2, but also not severe enough to hit the catastrophic tripwire. Because of the deny-by-default architecture, unknown commands or reversible writes fall into this bucket.

**Examples of General Blocked Commands:**
*   Any binary not explicitly listed in Tier 1 or Tier 2.
*   Commands that use the blocked privilege escalation prefixes `su`, `doas`, `runuser`, `pkexec` (and `sudo` in any non-bare form — with flags, an env assignment, or nested; the bare `sudo <read-only-command>` wrapper is allowed, see above).
*   Commands violating global syntax rules (e.g., containing forbidden shell metacharacters like `<`, `;`, `&`, `$`, `\n`).
*   Tier 2 binaries invoked with write, execute, or control subcommands (e.g., `docker run`, `iptables -A`, `systemctl restart`, `curl -o`).
*   Binaries invoked as absolute/relative paths instead of bare command names.

## Secret Redaction

The guard keeps the agent read-only, but "read-only" still means it reads sensitive files **as root** — `/etc/shadow`, private keys, database and application config, `docker inspect` output, `.env` files. Left alone, that material would flow into the model's context (and therefore the Anthropic API) and be quoted verbatim in the report's evidence and appendix. To prevent that, **all command output is passed through `redact()` (`src/agent/redact.py`) before it is shown to the model** — both `ssh_run` results in Phase 2 and the formatted baseline in Phase 1. Because the report is written by the model from what it saw, redacting at this boundary keeps secrets out of the report too. (The audit log stores no command output, so there is nothing to redact there.)

Redaction is deliberately **high-precision** — it targets a small set of unambiguous secret shapes rather than matching on keywords, so it does not mangle security-relevant *non-secrets* (e.g. `PasswordAuthentication yes` from `sshd -T`, or `password_encryption = scram-sha-256` from `postgresql.conf`, both of which are findings). What it masks:

* **Private keys** (PEM / OpenSSH) — the key body, keeping the `BEGIN`/`END` markers so the *presence* of a key is still a visible finding.
* **`/etc/shadow` password hashes** — the salt and hash, preserving the `$id$` prefix (a weak `$1$` MD5 hash is itself a finding).
* **Redis `requirepass` / `masterauth`** — both the config-file form and the `redis-cli CONFIG GET` output.
* **`NAME=VALUE` / `NAME: VALUE` secret assignments** — where the name ends in a secret word (`POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `*_SECRET`, `*_TOKEN`, `*_API_KEY`, `DB_PASS`, …). This covers `.env` files, `docker inspect` (the container `Env` array), compose files, systemd `Environment=` lines, and `my.cnf`.
* **Credentials embedded in URLs** — `scheme://user:PASSWORD@host` (e.g. a `DATABASE_URL`).
* **`.pgpass` lines** — the password field of `host:port:database:user:password`.

A redacted value keeps its first two and last two characters with dots between (`AKIA...9f`); anything eight characters or shorter is fully masked as `[redacted]`. Redaction is best-effort: it is pattern-based, so a secret in a format it does not model can still slip through. Enforcement lives in code and is unit-tested (`tests/test_redact.py`), including the non-secret cases that must survive untouched.

## Agent Feedback Loop

Because the AI agent operates under strict deny-by-default rules, it will inevitably attempt to run commands that get blocked. To handle this gracefully, the custom `ssh_run` tool intercepts all rejected commands *before* they ever reach the SSH connection.

Instead of silently failing or executing a partial command, the tool returns an explicit error back to the LLM formatted as:
`REJECTED (read-only guard): <reason>. Try a read-only command instead.`

This immediate, descriptive feedback loop allows the agent to understand exactly *why* its command failed (e.g., "binary 'awk' is not on the read-only allowlist") and quickly adapt its strategy by choosing an alternative, permitted command. Additionally, the agent is instructed to document falsely rejected read-only commands in its final report so developers can continuously improve the allowlist.
