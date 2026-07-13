"""Best-effort redaction of secret material in command output.

Applied to everything shown to the model — `ssh_run` results (Phase 2) and the
formatted Phase-1 baseline — so secrets the agent reads as root do not flow into
the model context (and therefore the Anthropic API) or the written report.

Redaction is deliberately HIGH-PRECISION. It targets a small set of unambiguous
secret shapes rather than broad keyword matching, so it does not mangle
security-relevant NON-secrets. In particular `PasswordAuthentication yes` (sshd)
and `password_encryption = scram-sha-256` (postgresql.conf) are findings, not
secrets, and must survive untouched — so we never redact on the word
"password". What we do redact:

  - Private-key bodies (PEM / OpenSSH). The BEGIN/END markers are kept so the
    *presence* of a key is still a visible finding; only the key bytes go.
  - /etc/shadow (and `getent shadow`) password hashes. The `$id$` algorithm
    prefix is preserved (a weak `$1$` MD5 hash is itself a finding); the salt
    and hash are redacted.
  - Redis `requirepass` / `masterauth` values, both the config-file form
    (`requirepass <value>`) and the `redis-cli CONFIG GET` two-line output.
  - `NAME=VALUE` / `NAME: VALUE` assignments whose NAME ends in a secret word
    (`POSTGRES_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `PGADMIN_DEFAULT_PASSWORD`,
    `*_SECRET`, `*_TOKEN`, `*_API_KEY`, `AWS_SECRET_ACCESS_KEY`, `DB_PASS`, …).
    This covers `.env` files, `docker inspect` output (the container `Env`
    array), compose files, systemd `Environment=` lines, and `my.cnf`. Precision
    lives in the NAME test: the secret word must be a whole underscore-delimited
    segment at the END of the name, so `password_encryption` (final segment
    "encryption") and `PasswordAuthentication yes` (space-separated, no `=`/`:`)
    are left alone, and a left-boundary check stops mid-word hits like
    `COMPASS=` or `BYPASS=`.
  - Credentials embedded in URLs (`scheme://user:PASSWORD@host`), e.g. a
    `DATABASE_URL` / `REDIS_URL`.
  - `.pgpass` lines (`host:port:database:user:password`) — the final
    colon-field. Detection is tight (field 1 a host, field 2 a port) so
    `/etc/passwd` and `/etc/shadow` are not affected.

A redacted value keeps its first two and last two characters with dots in
between (e.g. `AKIA...9f`). Anything <= 8 chars is fully masked as `[redacted]`
so short secrets are never partly revealed.
"""

from __future__ import annotations

import re

_FULL_MASK = "[redacted]"
# A value we already produced: two chars, three dots, two chars (`Su...23`).
# Recognised so redact() is idempotent (re-redacting must not shrink it).
_ALREADY_REDACTED = re.compile(r"^..\.\.\...$")


def redact_secret(value: str) -> str:
    """First two + last two characters with dots between; short values masked."""
    if value == _FULL_MASK or _ALREADY_REDACTED.match(value):
        return value
    if len(value) <= 8:
        return _FULL_MASK
    return f"{value[:2]}...{value[-2:]}"


# --- private keys -----------------------------------------------------------
_PEM_KEY = re.compile(
    r"(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----)(.*?)"
    r"(-----END [A-Z0-9 ]*PRIVATE KEY-----)",
    re.DOTALL,
)


def _redact_private_keys(text: str) -> str:
    return _PEM_KEY.sub(r"\1 [redacted private key] \3", text)


# --- shadow password hashes -------------------------------------------------
def _redact_hash(field: str) -> str:
    """Redact a crypt hash while preserving its `$id$` algorithm prefix."""
    if field.startswith("$"):
        parts = field.split("$")  # ['', id, salt, hash, ...]
        if len(parts) >= 3:
            return f"${parts[1]}$" + redact_secret("$".join(parts[2:]))
    return redact_secret(field)


def _redact_shadow(line: str) -> str | None:
    """A `user:$id$...:...` shadow line -> hash field redacted; else None.

    /etc/passwd lines have `x`/`*` in field 2, so the `$`-prefix test makes this
    fire only on real hashes.
    """
    parts = line.split(":")
    if len(parts) >= 2 and parts[1].startswith("$"):
        parts[1] = _redact_hash(parts[1])
        return ":".join(parts)
    return None


# --- redis auth directives --------------------------------------------------
_SECRET_DIRECTIVES = {"requirepass", "masterauth"}
_DIRECTIVE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<key>requirepass|masterauth)(?P<sep>[ \t]+)(?P<val>\S.*)$",
    re.IGNORECASE,
)


def _redact_directive(line: str) -> str | None:
    """`requirepass <value>` (config-file form) -> value redacted; else None."""
    m = _DIRECTIVE_RE.match(line)
    if not m:
        return None
    return (f"{m.group('indent')}{m.group('key')}{m.group('sep')}"
            f"{redact_secret(m.group('val').strip())}")


# --- KEY=VALUE / KEY: VALUE secret assignments ------------------------------
# (.env files, `docker inspect` Env arrays, compose, systemd Environment=, my.cnf)
# The NAME must END with a secret word as a whole `_`-delimited segment. The
# leading lookbehind `(?<![A-Za-z0-9_])` anchors the name to a real boundary so
# `COMPASS=`/`BYPASS=` (secret word not `_`-delimited) do not match, and because
# the secret word must sit immediately before the separator, `password_encryption`
# (final segment "encryption") is never touched. Group 2 captures the separator
# and any opening quote; the closing quote (if any) stays outside the match.
_SECRET_ASSIGN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"((?:[A-Za-z0-9]+_)*"
    r"(?:PASSWORD|PASSWD|PASSPHRASE|PASS|SECRET|TOKEN|APIKEY|CREDENTIALS?|"
    r"API_KEY|SECRET_ACCESS_KEY|SECRET_KEY|ACCESS_KEY|PRIVATE_KEY|"
    r"ENCRYPTION_KEY|SIGNING_KEY|AUTH_TOKEN|ACCESS_TOKEN))"
    r"(\s*[:=]\s*['\"]?)"
    r"([^\s'\",;]+)",
    re.IGNORECASE,
)


def _redact_assignments(text: str) -> str:
    return _SECRET_ASSIGN.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{redact_secret(m.group(3))}", text)


# --- credentials embedded in URLs (scheme://user:PASSWORD@host) --------------
# The user part may be empty (`redis://:pw@host`); host:port is never matched
# because the password must be immediately followed by `@`.
_URL_CRED = re.compile(r"(://[^\s:/@]*:)([^\s/@]+)(@)")


def _redact_url_creds(text: str) -> str:
    return _URL_CRED.sub(
        lambda m: f"{m.group(1)}{redact_secret(m.group(2))}{m.group(3)}", text)


# --- .pgpass lines (host:port:database:user:password) -----------------------
# The password is the final colon-field. Detection is tight so ordinary
# colon-delimited data is not touched: field 1 must be a host (`*`, `localhost`,
# or something containing a dot — an IP/FQDN) and field 2 a port (`*` or
# digits). /etc/passwd (field 1 has no dot; 7 fields with a non-numeric field 2)
# and /etc/shadow (field 2 starts with `$`) therefore never match.
def _redact_pgpass(line: str) -> str | None:
    parts = line.split(":")
    if len(parts) < 5:
        return None
    host, port = parts[0], parts[1]
    if not (host == "*" or host.lower() == "localhost" or "." in host):
        return None
    if not (port == "*" or port.isdigit()):
        return None
    if not parts[2] or not parts[3]:            # database and user non-empty
        return None
    password = ":".join(parts[4:])              # password may itself hold colons
    if not password:
        return None
    return ":".join(parts[:4]) + ":" + redact_secret(password)


def redact(text: str) -> str:
    """Redact secret material in `text`. Idempotent and newline-preserving."""
    if not text:
        return text

    text = _redact_private_keys(text)
    text = _redact_url_creds(text)
    text = _redact_assignments(text)

    lines = text.split("\n")
    out: list[str] = []
    redact_next = False  # `redis-cli CONFIG GET requirepass` puts the value on
    for line in lines:                                    # the following line.
        if redact_next:
            redact_next = False
            if line.strip():
                indent = line[:len(line) - len(line.lstrip())]
                out.append(indent + redact_secret(line.strip()))
                continue

        shadow = _redact_shadow(line)
        if shadow is not None:
            out.append(shadow)
            continue

        pgpass = _redact_pgpass(line)
        if pgpass is not None:
            out.append(pgpass)
            continue

        directive = _redact_directive(line)
        if directive is not None:
            out.append(directive)
            continue

        if line.strip().lower() in _SECRET_DIRECTIVES:
            redact_next = True

        out.append(line)

    return "\n".join(out)
