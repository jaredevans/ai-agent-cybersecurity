"""Detect the connecting user's privilege on the target host.

Best-effort, read-only probe used to decide whether Phase 1 prefixes its
baseline commands with `sudo`. Follows the identity.py pattern: fixed,
code-owned commands run through run_ssh with an injectable runner. Any
failure or ambiguity falls back to "do not use sudo", preserving the
root-only behavior the agent had before.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass

from agent.ssh_tool import run_ssh


@dataclass(frozen=True)
class Privilege:
    is_root: bool
    has_sudo: bool  # passwordless sudo verified to yield uid 0

    @property
    def use_sudo(self) -> bool:
        """Prefix baseline commands with sudo only when non-root AND we
        confirmed passwordless sudo escalates to root."""
        return not self.is_root and self.has_sudo


def _run(host, argv, runner) -> tuple[int | None, str]:
    try:
        result = run_ssh(host, [argv], runner=runner)
    except Exception:  # noqa: BLE001 - detection is best-effort
        return None, ""
    return result["exit_code"], result["stdout"]


def detect_privilege(host: str, *, runner=subprocess.run) -> Privilege:
    """Return the connecting user's Privilege on `host` (best-effort).

    A host with `Defaults requiretty` makes `sudo -n` over SSH (no TTY) fail;
    this probe then reports has_sudo=False and reads run unprivileged, which
    is the correct fail-safe behavior.
    """
    code, out = _run(host, ["id", "-u"], runner)
    if code == 0 and out.strip() == "0":
        return Privilege(is_root=True, has_sudo=False)

    # Non-root (or id failed): probe passwordless sudo escalation to root.
    scode, sout = _run(host, ["sudo", "-n", "id", "-u"], runner)
    has_sudo = scode == 0 and sout.strip() == "0"
    return Privilege(is_root=False, has_sudo=has_sudo)
