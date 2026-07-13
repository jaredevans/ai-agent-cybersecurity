"""Discover the scanned host's own identity (IPs + hostnames).

curl is normally restricted to loopback; the returned set widens that to the
host's own addresses and names so the agent can test URLs a web server is
configured to serve (e.g. nginx `server_name`). Sources, all read-only:
  - `hostname -I` (own interface IPs), `hostname -f`/`hostname` (own names);
  - `/etc/hosts` entries whose IP is loopback or one of this host's own IPs —
    a name the host maps to itself (curl honours /etc/hosts before DNS, so it
    always connects back to this host).
Names in /etc/hosts that point elsewhere are NOT included.
"""

from __future__ import annotations

import ipaddress
import subprocess

from agent.ssh_tool import run_ssh


def _is_self_ip(ip_str: str, self_ips: set[str]) -> bool:
    if ip_str in self_ips:
        return True
    try:
        return ipaddress.ip_address(ip_str).is_loopback
    except ValueError:
        return False


def _run(host, argv, runner) -> str:
    try:
        result = run_ssh(host, [argv], runner=runner)
    except Exception:  # noqa: BLE001 - identity discovery is best-effort
        return ""
    return result["stdout"] if result["exit_code"] == 0 else ""


def discover_self_hosts(host: str, *, runner=subprocess.run) -> frozenset[str]:
    """Return the target's own IPs and hostnames (lowercased, trailing dot
    stripped). Best-effort: unreachable or failing queries are skipped."""
    ips = {t.strip().lower() for t in _run(host, ["hostname", "-I"], runner).split()
           if t.strip()}

    names: set[str] = set()
    for argv in (["hostname", "-f"], ["hostname"]):
        for token in _run(host, argv, runner).split():
            name = token.strip().rstrip(".").lower()
            if name:
                names.add(name)

    # /etc/hosts names that map to loopback or one of this host's own IPs.
    for line in _run(host, ["cat", "/etc/hosts"], runner).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if _is_self_ip(parts[0].lower(), ips):
            for token in parts[1:]:
                name = token.strip().rstrip(".").lower()
                if name:
                    names.add(name)

    return frozenset(ips | names)
