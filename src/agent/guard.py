"""Read-only command guard. Pure functions, no I/O.

Three outcomes, reported via GuardResult.severity:
  - allowed  (severity="")            : on the read-only allowlist.
  - blocked  (severity="catastrophic"): matches the irreversible-damage
        denylist. Checked FIRST, before the allowlist, so it is a tripwire a
        mistaken allowlist entry cannot override.
  - blocked  (severity="write")       : everything else — not allowlisted but
        not catastrophic (a reversible/unknown write, or a global-rule
        violation such as shell metacharacters).

Deny-by-default is the primary control: a command runs only if Tier 1
(inherently read-only binaries, any args) or a Tier 2 rule (dual-use binaries,
explicitly allowlisted read invocations) affirmatively permits it. Tier 2 rules
allowlist read subcommands rather than blocklisting writes, because blocklists
are incomplete against a binary's full subcommand surface (e.g. `ip netns
exec`).
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    reason: str = ""
    argv: list[str] = field(default_factory=list)
    severity: str = ""  # "" (allowed), "catastrophic", or "write"
    # For an allowed command, the validated pipeline: one token-list per stage.
    # A single command is a one-stage pipeline; `argv` mirrors the first stage.
    pipeline: list[list[str]] = field(default_factory=list)


# Pipes (`|`) are allowed but handled by segmentation: every stage must
# independently pass the guard. All other shell metacharacters stay forbidden.
_FORBIDDEN_CHARS = set("><;&$`\n\r")
_PRIVILEGE_PREFIXES = {"sudo", "su", "doas", "runuser", "pkexec"}

# System roots whose recursive deletion / permission change is irreversible.
_SYSTEM_PATHS = {
    "/", "/*", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/usr", "/boot",
    "/var", "/root", "/home", "/dev", "/proc", "/sys", "/opt", "/srv", "/run",
}
_DEVICE_PREFIXES = ("/dev/sd", "/dev/nvme", "/dev/vd", "/dev/hd", "/dev/xvd",
                    "/dev/mmcblk", "/dev/mapper", "/dev/disk", "/dev/loop")
_CRITICAL_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/gshadow", "/etc/group", "/etc/fstab",
    "/etc/sudoers", "/boot/grub/grub.cfg", "/etc/default/grub",
}

# Binaries that are irreversibly destructive regardless of arguments.
_CATASTROPHIC_BINARIES = {
    "mkswap", "wipefs", "blkdiscard", "shred", "fdisk", "sfdisk", "cfdisk",
    "sgdisk", "parted", "cryptsetup", "pvremove", "vgremove", "lvremove",
    "mdadm", "shutdown", "reboot", "halt", "poweroff", "telinit",
    "grub-install", "userdel", "groupdel",
}


# ---------------------------------------------------------------------------
# Tier 1: inherently read-only binaries — any arguments permitted.
# Every entry must be UNABLE to write state or exec another program with ANY
# arguments. Binaries with set-*/install/exec/clock/mount/clear capabilities
# live in Tier 2 with an explicit read-only rule instead.
# ---------------------------------------------------------------------------
TIER1: frozenset[str] = frozenset({
    "lsb_release", "uname", "uptime", "cat", "head", "tail", "stat",
    "readlink", "realpath", "id", "who", "w", "last", "getent",
    "groups", "ps", "df", "du", "lsblk", "findmnt", "blkid", "ls",
    "dpkg-query", "netstat", "lscpu", "lsmod", "lsof",
    "printenv", "free", "vmstat", "grep", "getcap", "aa-status", "lastb",
    "which", "systemd-detect-virt",
    # NOTE: sort and uniq are deliberately NOT here — both can write a file
    # (sort -o/--output, uniq's second positional) so they are Tier 2 with a
    # rule that rejects those forms. The tools below have no file-write flag.
    "wc", "cut", "tr", "egrep", "fgrep",
    "getfacl", "lsattr", "lslogins", "apparmor_status",
})


def _first_verb(args: list[str]) -> str | None:
    """First non-flag token (subcommand for subcommand-style binaries)."""
    for a in args:
        if not a.startswith("-"):
            return a
    return None


# ---------------------------------------------------------------------------
# Catastrophic detection (the tripwire).
# ---------------------------------------------------------------------------
def _tokenize_best_effort(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _rm_is_recursive(args: list[str]) -> bool:
    for a in args:
        if a in {"--recursive", "--no-preserve-root"}:
            return True
        if a.startswith("-") and not a.startswith("--"):
            if "r" in a or "R" in a:
                return True
    return False


def _catastrophic_reason(command: str, tokens: list[str]) -> str | None:
    stripped = command.replace(" ", "")
    if stripped.startswith(":(){") or ":|:&" in stripped:
        return "fork bomb pattern"
    if ">" in command and any(dev in command for dev in _DEVICE_PREFIXES):
        return "redirection onto a block device"
    if not tokens:
        return None

    binary = tokens[0].rsplit("/", 1)[-1]  # basename, defeats /bin/rm etc.
    args = tokens[1:]

    if binary in _CATASTROPHIC_BINARIES:
        return f"irreversibly destructive command '{binary}'"
    if binary == "mkfs" or binary.startswith("mkfs."):
        return f"filesystem creation '{binary}'"
    if binary == "rm" and _rm_is_recursive(args):
        return "recursive file deletion"
    if binary == "dd":
        for a in args:
            if a.startswith("of=") and any(
                a[3:].startswith(dev) for dev in _DEVICE_PREFIXES
            ):
                return "dd writing to a block device"
    if binary == "init" and any(a in {"0", "6"} for a in args):
        return "init runlevel change (halt/reboot)"
    if binary == "kill" and "-1" in args and any(
        a in {"-9", "-KILL", "-SIGKILL", "-15", "-TERM", "-SIGTERM", "-s"}
        for a in args
    ):
        return "kill signalling all processes"
    if binary in {"chmod", "chown", "chgrp"}:
        recursive = any(
            a == "--recursive"
            or (a.startswith("-") and not a.startswith("--") and "R" in a)
            for a in args
        )
        if recursive and any(a in _SYSTEM_PATHS for a in args):
            return f"recursive {binary} on a system path"
    if binary == "systemctl":
        verb = _first_verb(args)
        if verb in {"isolate", "poweroff", "reboot", "halt", "kexec",
                    "emergency", "rescue", "hibernate", "suspend"}:
            return f"systemctl {verb} (availability change)"
    if binary in {"tee", "cp", "mv", "ln", "install", "truncate"}:
        if any(a in _CRITICAL_FILES for a in args):
            return f"{binary} targeting a critical system file"
    return None


# ---------------------------------------------------------------------------
# Tier 2 rules: allowlist read invocations; deny everything else.
# ---------------------------------------------------------------------------
def _ip_command_verb(args: list[str]) -> str | None:
    non_flags = [a for a in args if not a.startswith("-")]
    # non_flags[0] = object, non_flags[1] = command (if present)
    if len(non_flags) >= 2:
        return non_flags[1]
    return None


def _rule_ip(args: list[str]) -> tuple[bool, str]:
    if "exec" in args:
        return False, "ip exec (namespace command execution) is blocked"
    if any(a in {"-b", "-batch", "--batch", "-force"} for a in args):
        return False, "ip -batch (execute commands from a file) is blocked"
    verb = _ip_command_verb(args)
    if verb is None or verb in {"show", "list", "get"}:
        return True, ""
    return False, f"ip command '{verb}' is not a read operation"


def _rule_iptables(args: list[str]) -> tuple[bool, str]:
    write = {"-A", "--append", "-I", "--insert", "-D", "--delete", "-R",
             "--replace", "-F", "--flush", "-X", "--delete-chain", "-N",
             "--new-chain", "-P", "--policy", "-Z", "--zero", "-E",
             "--rename-chain"}
    read = {"-L", "--list", "-S", "--list-rules"}
    if any(a in write for a in args):
        return False, "iptables write/flush/policy flag is blocked"
    if not any(a in read for a in args):
        return False, "iptables requires a read flag (-L or -S)"
    return True, ""


def _rule_nft(args: list[str]) -> tuple[bool, str]:
    if "-f" in args or "--file" in args:
        return False, "nft -f (load ruleset from file) is blocked"
    if _first_verb(args) == "list":
        return True, ""
    return False, "nft only permits 'list'"


def _rule_systemctl(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb is None:
        return True, ""
    if verb in {"status", "show", "cat", "get-default", "help",
                "show-environment"}:
        return True, ""
    if verb.startswith("list-") or verb.startswith("is-"):
        return True, ""
    return False, f"systemctl subcommand '{verb}' is not a read operation"


def _rule_sysctl(args: list[str]) -> tuple[bool, str]:
    read_flags = {"-a", "--all", "-A", "-X", "-n", "--values", "-N",
                  "--names", "-e", "--ignore", "-b", "--binary", "-d",
                  "--describe", "-h"}
    for a in args:
        if "=" in a:
            return False, "sysctl assignment (key=value) is blocked"
        if a.startswith("-") and a not in read_flags:
            return False, f"sysctl flag '{a}' is not a read flag"
    return True, ""


def _rule_ufw(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb is None or verb in {"status", "show"}:
        return True, ""
    return False, "ufw only permits 'status' / 'show'"


def _rule_apt(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb in {"list", "show", "policy", "search", "depends", "rdepends"}:
        return True, ""
    return False, f"apt subcommand '{verb}' is not a read operation"


def _rule_snap(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb in {"list", "info", "version", "connections", "changes"}:
        return True, ""
    return False, f"snap subcommand '{verb}' is not a read operation"


def _rule_journalctl(args: list[str]) -> tuple[bool, str]:
    write = {"--rotate", "--flush", "--sync", "--relinquish-var",
             "--smart-relinquish-var", "--setup-keys", "--update-catalog"}
    for a in args:
        if a in write or a.startswith("--vacuum-"):
            return False, f"journalctl maintenance flag '{a}' is blocked"
    return True, ""


def _rule_crontab(args: list[str]) -> tuple[bool, str]:
    if "-l" not in args:
        return False, "crontab requires -l (list)"
    if any(a in {"-e", "-r", "-i"} for a in args):
        return False, "crontab edit/remove flag is blocked"
    return True, ""


def _rule_find(args: list[str]) -> tuple[bool, str]:
    write = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint",
             "-fprintf", "-fprint0", "-fls"}
    for a in args:
        if a in write:
            return False, f"find action '{a}' is blocked"
    return True, ""


def _rule_sshd(args: list[str]) -> tuple[bool, str]:
    if "-T" in args and "-D" not in args:
        return True, ""
    return False, "sshd only permits -T (config dump)"


def _rule_auditctl(args: list[str]) -> tuple[bool, str]:
    if args and all(a in {"-l", "-s", "--list", "--status"} for a in args):
        return True, ""
    return False, "auditctl only permits -l / -s"


def _rule_dmesg(args: list[str]) -> tuple[bool, str]:
    write = {"-C", "--clear", "-c", "--read-clear", "-n", "--console-level",
             "-D", "--console-off", "-E", "--console-on"}
    for a in args:
        if a in write:
            return False, f"dmesg control flag '{a}' is blocked"
    return True, ""


def _rule_resolvectl(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb is None or verb in {"status", "query", "statistics"}:
        return True, ""
    return False, f"resolvectl subcommand '{verb}' is not a read operation"


def _rule_hostnamectl(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb is None or verb == "status":
        return True, ""
    return False, f"hostnamectl subcommand '{verb}' is not a read operation"


_DATE_CLOCK_ARG = re.compile(r"^[0-9]{8,}(\.[0-9]{2})?$")


def _rule_date(args: list[str]) -> tuple[bool, str]:
    for a in args:
        if a in {"-s", "--set"} or a.startswith("--set="):
            return False, "date --set (clock change) is blocked"
        if not a.startswith(("-", "+")) and _DATE_CLOCK_ARG.match(a):
            return False, "date positional clock-set argument is blocked"
    return True, ""


def _rule_arp(args: list[str]) -> tuple[bool, str]:
    write = {"-s", "--set", "-d", "--delete", "-f", "--file"}
    for a in args:
        if a in write:
            return False, f"arp modify flag '{a}' is blocked"
    return True, ""


def _rule_mount(args: list[str]) -> tuple[bool, str]:
    if not args:
        return True, ""
    return False, "mount permits no arguments (use findmnt for filtered reads)"


def _rule_dpkg(args: list[str]) -> tuple[bool, str]:
    read = {"-l", "--list", "-L", "--listfiles", "-s", "--status", "-S",
            "--search", "-p", "--print-avail", "--get-selections", "-V",
            "--verify", "--audit", "-c", "--contents", "-I", "--info"}
    write = {"-i", "--install", "-r", "--remove", "-P", "--purge",
             "--unpack", "--configure", "--update-avail", "--merge-avail",
             "--set-selections", "--clear-selections",
             "--forget-old-unavail", "-a", "--pending"}
    if any(a in write for a in args):
        return False, "dpkg write operation is blocked"
    if any(a in read for a in args):
        return True, ""
    return False, "dpkg requires a read operation (-l, -L, -s, -S, ...)"


def _rule_file(args: list[str]) -> tuple[bool, str]:
    if "-C" in args or "--compile" in args:
        return False, "file --compile writes a magic database and is blocked"
    return True, ""


def _rule_chage(args: list[str]) -> tuple[bool, str]:
    write = {"-d", "--lastday", "-E", "--expiredate", "-m", "--mindays",
             "-M", "--maxdays", "-W", "--warndays", "-I", "--inactive"}
    for a in args:
        if a in write or (a.startswith("--") and a.split("=", 1)[0] in write):
            return False, "chage write flag is blocked"
    if "-l" in args or "--list" in args:
        return True, ""
    return False, "chage requires -l (list); other forms modify password aging"


def _rule_ss(args: list[str]) -> tuple[bool, str]:
    if any(a in {"-K", "--kill"} for a in args):
        return False, "ss -K (destroy matching sockets) is blocked"
    return True, ""


def _rule_lastlog(args: list[str]) -> tuple[bool, str]:
    if any(a in {"-C", "--clear", "-S", "--set"} for a in args):
        return False, "lastlog -C/-S (modify login records) is blocked"
    return True, ""


def _rule_apt_cache(args: list[str]) -> tuple[bool, str]:
    read = {"showpkg", "showsrc", "stats", "dump", "dumpavail", "unmet",
            "search", "show", "depends", "rdepends", "pkgnames", "dotty",
            "xvcg", "policy", "madison"}
    verb = _first_verb(args)
    if verb is None or verb in read:
        return True, ""
    return False, f"apt-cache subcommand '{verb}' is not a read operation"


# Docker: allowlist read-only subcommands. Management groups (container, image,
# ...) permit only read verbs; run/exec/rm/build/prune/... are denied by default.
_DOCKER_READ_TOP = {
    "ps", "images", "version", "info", "logs", "stats", "top", "port",
    "diff", "history", "events", "inspect",
}
_DOCKER_GROUPS = {
    "container", "image", "network", "volume", "system", "node", "service",
    "stack", "context", "config", "secret", "plugin", "builder", "buildx",
    "swarm", "trust", "manifest", "compose", "checkpoint",
}
_DOCKER_GROUP_READ = {
    "ls", "list", "inspect", "df", "info", "events", "ps", "version", "top",
    "logs", "stats", "history", "port", "diff",
}


# Global connection flags that point the client at another daemon/context.
# Matched by prefix so joined shorthand (`-Htcp://...`, `-cremote`) and `=`
# forms are caught. `-c` is the short alias of `--context`.
_DOCKER_DANGER_PREFIXES = ("-H", "--host", "-c", "--context", "--config",
                           "--tls")


def _rule_hostname(args: list[str]) -> tuple[bool, str]:
    """Allow read forms (bare, -I/-f/-A/-s/-d/...); block name-setting forms,
    including attached/`=` variants (`-F/etc/hostname`, `--file=...`)."""
    write = {"-b", "--boot", "-F", "--file"}
    for a in args:
        if a.split("=", 1)[0] in write or a.startswith(("-F", "--file")):
            return False, "hostname name-setting form is blocked"
        if not a.startswith("-"):
            return False, "hostname with an argument sets the name and is blocked"
    return True, ""


def _rule_docker(args: list[str]) -> tuple[bool, str]:
    for a in args:
        if a.startswith(_DOCKER_DANGER_PREFIXES):
            return False, "docker daemon/context/TLS flags are blocked"
    non_flags = [a for a in args if not a.startswith("-")]
    if not non_flags:
        return False, "docker requires a read subcommand"
    verb = non_flags[0]
    if verb in _DOCKER_READ_TOP:
        return True, ""
    if verb in _DOCKER_GROUPS:
        sub = non_flags[1] if len(non_flags) > 1 else None
        if sub in _DOCKER_GROUP_READ:
            return True, ""
        return False, f"docker {verb} '{sub}' is not a read operation"
    return False, f"docker subcommand '{verb}' is not a read operation"


# Curl: strict deny-by-default allowlist of read-only, non-egress flags, and
# EVERY URL target must be loopback (local probing only) so the agent cannot
# write files, upload, follow redirects off-host, proxy, or beacon out.
# Clustered short flags (e.g. `-sI`) are NOT accepted — pass them separately
# (`-s -I`) — so a write flag can never hide inside a cluster.
# Deliberately minimal: only flags needed to probe a local HTTP endpoint.
# Excluded on purpose because they read/write files or enable egress:
# -o/-O/-T (write/upload), -w/--write-out (%output{} writes a file),
# -b/--cookie & -e/--referer (@file reads), -K/--config, -x/--proxy, -L
# (off-host redirect), --resolve/--connect-to/--url (target remap/egress).
_CURL_SHORT_NOVALUE = {"-s", "-S", "-I", "-v", "-k", "-f"}
# The letters of the no-value short flags, for validating clusters like `-sI`.
_CURL_NOVALUE_CHARS = set("sSIvkf")
_CURL_SHORT_VALUE = {"-m", "-H", "-A"}
_CURL_LONG_NOVALUE = {
    "--silent", "--show-error", "--head", "--insecure", "--verbose",
    "--fail", "--compressed", "--http1.1", "--http1.0", "--http2",
    "--no-progress-meter",
}
_CURL_LONG_VALUE = {
    "--max-time", "--connect-timeout", "--header", "--user-agent",
}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _target_host_allowed(host: str | None,
                         allowed_hosts: frozenset,
                         client: str) -> tuple[bool, str]:
    """Shared egress guard for network clients (curl, redis-cli, and any future
    client). Returns (True, "") when `host` is a permitted local target, else
    (False, reason). Keeping this in one audited place ensures no client can
    drift into permitting an outbound connection: each client passes the set of
    hosts it may reach (loopback only, or loopback plus the scanned host's own
    addresses) and the membership decision is made here.
    """
    if host in allowed_hosts:
        return True, ""
    return False, (f"{client} may only target this host; "
                   f"'{host}' is not a permitted target")


def _rule_curl(args: list[str],
               allowed_hosts: frozenset = None) -> tuple[bool, str]:
    if allowed_hosts is None:
        allowed_hosts = _LOOPBACK_HOSTS
    urls: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            name = a.split("=", 1)[0]
            if "=" in a:
                if name in _CURL_LONG_VALUE or name in _CURL_LONG_NOVALUE:
                    i += 1
                    continue
                return False, f"curl flag '{name}' is not allowed"
            if a in _CURL_SHORT_NOVALUE or a in _CURL_LONG_NOVALUE:
                i += 1
                continue
            if a in _CURL_SHORT_VALUE or a in _CURL_LONG_VALUE:
                i += 2  # skip this flag's value token
                continue
            # A cluster of no-value read flags (e.g. -sI, -skv) is safe; any
            # write/value/unknown char in the cluster falls through to reject.
            if (not a.startswith("--") and len(a) > 2
                    and all(ch in _CURL_NOVALUE_CHARS for ch in a[1:])):
                i += 1
                continue
            return False, (f"curl flag '{a}' is not allowed "
                           "(write/egress flag, or a value flag clustered — "
                           "pass value flags separately)")
        urls.append(a)
        i += 1
    if not urls:
        return False, "curl requires a permitted URL target"
    for u in urls:
        parsed = urlparse(u if "://" in u else f"//{u}")
        if parsed.scheme not in ("", "http", "https"):
            return False, "curl only permits http/https targets"
        ok, reason = _target_host_allowed(parsed.hostname, allowed_hosts,
                                          "curl")
        if not ok:
            return False, reason
    return True, ""


def _rule_nginx(args: list[str]) -> tuple[bool, str]:
    # -s sends a control signal (stop/quit/reload/reopen); bare nginx starts it.
    if "-s" in args:
        return False, "nginx -s (signal) is blocked"
    if any(a in {"-T", "-t", "-v", "-V"} for a in args):
        return True, ""
    return False, "nginx requires -T/-t/-v/-V (dump/test config or version)"


def _rule_apache2ctl(args: list[str]) -> tuple[bool, str]:
    # -D is a "define startup parameter" flag (bare -D starts the server), NOT a
    # read action; -S/-M already cover the dump use cases.
    if any(a in {"-t", "-S", "-M", "-V", "-v", "-l", "-L"} for a in args):
        # -k start/stop/... is control; -t/-S/-M/... are read/test.
        if "-k" in args:
            return False, "apache2ctl -k (start/stop/restart) is blocked"
        return True, ""
    verb = _first_verb(args)
    if verb in {"configtest", "status", "fullstatus"}:
        return True, ""
    return False, "apache2ctl only permits config-test/status/version reads"


def _rule_pm2(args: list[str]) -> tuple[bool, str]:
    read = {"list", "ls", "l", "jlist", "prettylist", "status", "show",
            "describe", "info", "id", "monit", "logs", "report", "prometheus"}
    verb = _first_verb(args)
    if verb in read:
        return True, ""
    return False, f"pm2 subcommand '{verb}' is not a read operation"


def _rule_passwd(args: list[str]) -> tuple[bool, str]:
    if not any(a in {"-S", "--status"} for a in args):
        return False, "passwd only permits -S (status)"
    write = {"-d", "--delete", "-l", "--lock", "-u", "--unlock", "-e",
             "--expire", "-x", "--maximum", "-n", "--minimum", "-w",
             "--warning", "-i", "--inactive"}
    if any(a in write for a in args):
        return False, "passwd write flag is blocked"
    return True, ""


def _rule_ssh_keygen(args: list[str]) -> tuple[bool, str]:
    # Allowlist-strict: require a read op (-l/-F/-B) and permit only read flags.
    # Any other flag (e.g. -H rewrites known_hosts, -R/-p/-t/-k write) → reject.
    if not any(a in {"-l", "-F", "-B"} for a in args):
        return False, "ssh-keygen only permits -l/-F/-B (read fingerprints)"
    allowed = {"-l", "-F", "-B", "-f", "-E", "-v"}
    for a in args:
        if a.startswith("-") and a not in allowed:
            return False, f"ssh-keygen flag '{a}' is not a read-only flag"
    return True, ""


def _rule_pro(args: list[str]) -> tuple[bool, str]:
    # `api` is intentionally excluded: `pro api` reaches state-changing
    # endpoints (services.enable/disable, magic-attach), not just reads.
    read = {"status", "security-status", "version", "about"}
    verb = _first_verb(args)
    if verb is None or verb in read:
        return True, ""
    return False, f"pro subcommand '{verb}' is not a read operation"


# openssl is powerful and dual-use: allowlist inspection subcommands and reject
# any file-writing flag. Generators/servers (genrsa, req, ca, enc, rand,
# s_server, ...) are excluded by not being in the read-subcommand set.
_OPENSSL_READ_SUBCMDS = {
    "x509", "crl", "verify", "asn1parse", "dgst", "ciphers", "version",
    "errstr", "nseq",
}
# Allowlist of read-only flags across the allowed inspection subcommands. Any
# flag NOT listed — file writers (-out/-keyout/...), code-exec vectors
# (-provider/-engine/-config), egress (-crl_download), unknown or future flags,
# and any alias/abbreviation — is rejected. Values are operands (non-flag
# tokens) and pass freely; only `-`-prefixed tokens are gated.
_OPENSSL_READ_FLAGS = {
    # input / format / trust anchors (read)
    "-in", "-inform", "-passin", "-CAfile", "-CApath", "-CAstore",
    "-no-CAfile", "-no-CApath", "-no-CAstore", "-untrusted", "-trusted",
    # display / output-control (to stdout)
    "-noout", "-text", "-help", "-nameopt", "-certopt", "-dateopt", "-a",
    # x509 inspection
    "-fingerprint", "-subject", "-issuer", "-subject_hash", "-issuer_hash",
    "-subject_hash_old", "-issuer_hash_old", "-hash", "-dates", "-startdate",
    "-enddate", "-checkend", "-purpose", "-pubkey", "-modulus", "-serial",
    "-email", "-ocsp_uri", "-ocspid", "-alias", "-ext", "-nocert",
    "-next_serial", "-checkhost", "-checkemail", "-checkip",
    # crl inspection
    "-crlnumber", "-lastupdate", "-nextupdate", "-verify",
    # verify options (read-only checks)
    "-verbose", "-show_chain", "-policy", "-policy_check", "-policy_print",
    "-attime", "-no_check_time", "-check_ss_sig", "-crl_check",
    "-crl_check_all", "-explicit_policy", "-inhibit_any", "-inhibit_map",
    "-x509_strict", "-ignore_critical", "-issuer_checks", "-partial_chain",
    "-trusted_first", "-auth_level", "-verify_depth", "-verify_email",
    "-verify_hostname", "-verify_ip", "-verify_name", "-allow_proxy_certs",
    "-extended_crl", "-use_deltas",
    # asn1parse
    "-offset", "-length", "-dump", "-dlimit", "-oid", "-strparse", "-item",
    "-i",
    # dgst (all output to stdout)
    "-hex", "-binary", "-c", "-r", "-hmac", "-mac", "-macopt", "-list",
    # ciphers
    "-v", "-V", "-s", "-stdname", "-convert", "-ciphersuites", "-psk", "-srp",
    # protocol selectors
    "-tls1", "-tls1_1", "-tls1_2", "-tls1_3",
    # digest algorithms (dgst, x509 -fingerprint)
    "-md5", "-sha1", "-sha224", "-sha256", "-sha384", "-sha512", "-sha3-224",
    "-sha3-256", "-sha3-384", "-sha3-512", "-blake2b512", "-blake2s256",
    "-ripemd160", "-sm3", "-shake128", "-shake256",
}


def _rule_openssl(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb not in _OPENSSL_READ_SUBCMDS:
        return False, (f"openssl subcommand '{verb}' is not an allowed "
                       "read/inspection operation")
    for a in args:
        flag = a.split("=", 1)[0]
        if not flag.startswith("-"):
            continue  # operand (file/string), a read input
        # `--opt` == `-opt` in openssl; normalize so no alias slips the list.
        canonical = "-" + flag.lstrip("-")
        if canonical not in _OPENSSL_READ_FLAGS:
            return False, f"openssl flag '{flag}' is not an allowed read-only flag"
    return True, ""


def _rule_postconf(args: list[str]) -> tuple[bool, str]:
    # Write flags: -e (edit), -# (comment out), -X (remove parameter),
    # -M/-F (edit master.cf). -X takes bare parameter names (no '='), so it
    # must be listed explicitly rather than relying on the '=' check.
    write = {"-e", "-#", "-M", "-F", "-X"}
    for a in args:
        if (a in write or a.startswith("-e") or a.startswith("-#")
                or a.startswith("-X") or "=" in a):
            return False, "postconf configuration edit is blocked"
    return True, ""


def _rule_fail2ban_client(args: list[str]) -> tuple[bool, str]:
    verb = _first_verb(args)
    if verb == "status":
        return True, ""
    return False, f"fail2ban-client subcommand '{verb}' is not a read operation (only 'status' is permitted)"


def _rule_sort(args: list[str]) -> tuple[bool, str]:
    """sort streams its input to stdout, but -o/--output writes a file and
    --compress-program executes a program — both defeat read-only. Block them,
    including GNU long-option abbreviations (--out) and short-flag clusters
    (-uofile), while allowing ordinary read/filter flags and input files."""
    for a in args:
        name = a.split("=", 1)[0]
        if name.startswith("--") and len(name) > 2:
            if "--output".startswith(name):
                return False, "sort --output writes to a file and is blocked"
            if "--compress-program".startswith(name):
                return False, ("sort --compress-program can execute a program "
                               "and is blocked")
        elif name.startswith("-") and "o" in name:
            # short-option cluster: 'o' is always sort's output-file flag
            return False, "sort -o (write to file) is blocked"
    return True, ""


_UNIQ_VALUE_FLAGS = {"-f", "-s", "-w",
                     "--skip-fields", "--skip-chars", "--check-chars"}


def _rule_uniq(args: list[str]) -> tuple[bool, str]:
    """uniq's second positional argument is an OUTPUT file it writes. Permit at
    most one positional (the input file, or '-' for stdin), rejecting the write
    form. Values consumed by -f/-s/-w are not counted as positionals."""
    positionals = 0
    expect_value = False
    for a in args:
        if expect_value:
            expect_value = False
            continue
        if a.startswith("-") and a != "-":
            if a in _UNIQ_VALUE_FLAGS:
                expect_value = True
            continue
        positionals += 1
        if positionals >= 2:
            return False, ("uniq writes its second file argument; only a single "
                           "input file (or stdin) is permitted")
    return True, ""


# redis-cli is a full Redis client — a gateway to server-side RCE
# (CONFIG SET dir + SAVE, MODULE LOAD, EVAL), arbitrary egress (-h/-u to any
# host), and local file writes (--rdb). It is permitted only in a tightly
# locked-down read-only form: loopback target, a small flag allowlist, and an
# exact read-subcommand allowlist. Anything not allowlisted fails closed.
_REDIS_NOVALUE_FLAGS = {"-3", "--raw", "--no-raw", "--askpass",
                        "--no-auth-warning"}
_REDIS_VALUE_FLAGS = {"-p", "-n", "-t", "-a", "--user", "--pass"}


def _rule_redis_cli(args: list[str]) -> tuple[bool, str]:
    words: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith("-"):
            if a == "-h":
                # target host must be a permitted local target (egress / SSRF
                # defense), enforced via the shared _target_host_allowed helper
                host = args[i + 1] if i + 1 < len(args) else ""
                ok, reason = _target_host_allowed(host, _LOOPBACK_HOSTS,
                                                  "redis-cli")
                if not ok:
                    return False, reason
                i += 2
                continue
            if a in _REDIS_NOVALUE_FLAGS:
                i += 1
                continue
            if a in _REDIS_VALUE_FLAGS:
                i += 2  # skip this flag's value token
                continue
            return False, (f"redis-cli flag '{a}' is not allowed "
                           "(write/egress/exec or unknown flag)")
        words.append(a)
        i += 1

    if not words:
        return False, "redis-cli requires a read-only subcommand"
    cmd = words[0].upper()
    sub = words[1].upper() if len(words) > 1 else None
    if cmd in ("PING", "INFO"):
        return True, ""
    if cmd == "CONFIG":
        if sub == "GET":
            return True, ""
        return False, "redis-cli CONFIG only permits GET (read)"
    if cmd == "CLIENT":
        if sub == "LIST":
            return True, ""
        return False, "redis-cli CLIENT only permits LIST (read)"
    return False, (f"redis-cli subcommand '{words[0]}' is not a permitted read "
                   "operation (only PING, INFO, CONFIG GET, CLIENT LIST)")


# SQL clients (mysql, psql) execute arbitrary SQL via -e/-c, and SQL is itself
# a file-read/file-write/RCE surface (INTO OUTFILE, COPY ... FROM PROGRAM,
# pg_read_file, psql '\!' shell escapes, ...). Rather than try to prove a SQL
# string is read-only (a fragile denylist), we permit only the informational
# modes that take NO SQL at all.
def _rule_mysql(args: list[str]) -> tuple[bool, str]:
    # --version is mysql's only non-SQL, non-connecting mode. Anything else
    # (a query via -e, file I/O, or an interactive session) is blocked.
    if args and all(a in ("-V", "--version") for a in args):
        return True, ""
    return False, ("mysql is restricted to --version; running SQL (-e), file "
                   "I/O, or an interactive session is not permitted")


_PSQL_NOVALUE = {"-l", "--list", "-V", "--version", "-w", "--no-password"}
_PSQL_VALUE = {"-p", "--port", "-U", "--username", "-d", "--dbname"}
_PSQL_INFO = {"-l", "--list", "-V", "--version"}


def _rule_psql(args: list[str]) -> tuple[bool, str]:
    # Permit only --version and -l/--list (database listing + live auth probe),
    # with loopback connection/auth flags. No -c/-f/-o/-L, no '\' meta-command,
    # no interactive session: those reach arbitrary SQL, files, or a shell.
    has_info = False
    i = 0
    while i < len(args):
        a = args[i]
        if not a.startswith("-"):
            return False, (f"psql positional argument '{a}' is not allowed "
                           "(use -d/-U flags)")
        name = a.split("=", 1)[0]
        if name in ("-h", "--host"):
            host = a.split("=", 1)[1] if "=" in a else (
                args[i + 1] if i + 1 < len(args) else "")
            ok, reason = _target_host_allowed(host, _LOOPBACK_HOSTS, "psql")
            if not ok:
                return False, reason
            i += 1 if "=" in a else 2
            continue
        if a in _PSQL_NOVALUE:
            if a in _PSQL_INFO:
                has_info = True
            i += 1
            continue
        if name in _PSQL_VALUE:
            i += 1 if "=" in a else 2
            continue
        return False, (f"psql flag '{a}' is not allowed (no arbitrary SQL; "
                       "only --version and -l/--list)")
    if not has_info:
        return False, ("psql requires -l/--list or --version; interactive or "
                       "query (-c/-f) use is blocked")
    return True, ""


TIER2_RULES: dict[str, Callable[[list[str]], tuple[bool, str]]] = {
    "postconf": _rule_postconf,
    "fail2ban-client": _rule_fail2ban_client,
    "sort": _rule_sort,
    "uniq": _rule_uniq,
    "redis-cli": _rule_redis_cli,
    "mysql": _rule_mysql,
    "psql": _rule_psql,
    "openssl": _rule_openssl,
    "ip": _rule_ip,
    "chage": _rule_chage,
    "ss": _rule_ss,
    "lastlog": _rule_lastlog,
    "docker": _rule_docker,
    "hostname": _rule_hostname,
    "nginx": _rule_nginx,
    "apache2ctl": _rule_apache2ctl,
    "apachectl": _rule_apache2ctl,
    "pm2": _rule_pm2,
    "passwd": _rule_passwd,
    "ssh-keygen": _rule_ssh_keygen,
    "pro": _rule_pro,
    "ubuntu-advantage": _rule_pro,
    "apt-cache": _rule_apt_cache,
    "iptables": _rule_iptables,
    "ip6tables": _rule_iptables,
    "nft": _rule_nft,
    "systemctl": _rule_systemctl,
    "sysctl": _rule_sysctl,
    "ufw": _rule_ufw,
    "apt": _rule_apt,
    "snap": _rule_snap,
    "journalctl": _rule_journalctl,
    "crontab": _rule_crontab,
    "find": _rule_find,
    "sshd": _rule_sshd,
    "auditctl": _rule_auditctl,
    "dmesg": _rule_dmesg,
    "resolvectl": _rule_resolvectl,
    "hostnamectl": _rule_hostnamectl,
    "date": _rule_date,
    "arp": _rule_arp,
    "mount": _rule_mount,
    "dpkg": _rule_dpkg,
    "file": _rule_file,
}


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------
def _deny_write(reason: str) -> GuardResult:
    return GuardResult(allowed=False, reason=reason, argv=[], severity="write")


def _split_pipeline(tokens: list[str]) -> list[list[str]]:
    """Split a token list into pipeline stages on bare `|` operator tokens.

    Because we split the SHLEX-tokenized list (not the raw string), a quoted
    pipe such as `grep 'a|b'` stays inside one token and is never treated as a
    stage separator.
    """
    stages: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok == "|":
            stages.append(current)
            current = []
        else:
            current.append(tok)
    stages.append(current)
    return stages


def _check_stage(seg: list[str],
                 self_hosts: frozenset = frozenset()) -> GuardResult:
    """Validate one pipeline stage (a token list). Returns allowed argv=seg."""
    cat = _catastrophic_reason(" ".join(seg), seg)
    if cat is not None:
        return GuardResult(allowed=False, reason=f"CATASTROPHIC: {cat}",
                           argv=[], severity="catastrophic")

    binary = seg[0]
    if "/" in binary or binary.startswith("."):
        return _deny_write("binary must be a bare command name, not a path")
    if binary in _PRIVILEGE_PREFIXES:
        return _deny_write(f"privilege prefix '{binary}' is not allowed")

    args = seg[1:]
    if binary in TIER1:
        return GuardResult(allowed=True, reason="", argv=seg, severity="")

    # curl is host-aware: loopback plus the target's own IPs/hostnames.
    if binary == "curl":
        ok, reason = _rule_curl(args, _LOOPBACK_HOSTS | self_hosts)
        if ok:
            return GuardResult(allowed=True, reason="", argv=seg, severity="")
        return _deny_write(reason)

    rule = TIER2_RULES.get(binary)
    if rule is not None:
        ok, reason = rule(args)
        if ok:
            return GuardResult(allowed=True, reason="", argv=seg, severity="")
        return _deny_write(reason)

    return _deny_write(f"binary '{binary}' is not on the read-only allowlist")


def check_command(command: str,
                  self_hosts: frozenset = frozenset()) -> GuardResult:
    """Validate a (possibly piped) command.

    `self_hosts` is an optional set of additional hosts curl may target (the
    scanned host's own IPs/hostnames), on top of loopback. Empty by default, so
    with no self-host context curl stays loopback-only.
    """
    tokens = _tokenize_best_effort(command)

    # Tripwire first, on the whole command: catches fork bombs and
    # redirect-to-device patterns that carry forbidden characters.
    cat = _catastrophic_reason(command, tokens)
    if cat is not None:
        return GuardResult(allowed=False, reason=f"CATASTROPHIC: {cat}",
                           argv=[], severity="catastrophic")

    # Global rules (pipe excluded — handled by segmentation below).
    if any(ch in _FORBIDDEN_CHARS for ch in command):
        return _deny_write("command contains a forbidden shell metacharacter")
    try:
        toks = shlex.split(command)
    except ValueError as exc:
        return _deny_write(f"could not parse command: {exc}")
    if not toks:
        return _deny_write("empty command")

    # Every pipeline stage must independently pass the guard.
    pipeline: list[list[str]] = []
    for seg in _split_pipeline(toks):
        if not seg:
            return _deny_write("empty pipeline stage")
        verdict = _check_stage(seg, self_hosts)
        if not verdict.allowed:
            return verdict
        pipeline.append(list(verdict.argv))

    return GuardResult(allowed=True, reason="", argv=pipeline[0],
                       severity="", pipeline=pipeline)
