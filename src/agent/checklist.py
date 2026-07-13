"""Baseline reconnaissance commands, by category (Phase 1).

Every command here MUST pass the read-only guard (see tests/test_checklist.py).
Claude runs additional read-only commands adaptively in Phase 2.
"""

from __future__ import annotations

CHECKLIST: dict[str, list[str]] = {
    "System & kernel": [
        "cat /etc/os-release",
        "lsb_release -a",
        "uname -a",
        "uptime",
        "hostnamectl",
        "systemd-detect-virt",
        "lscpu",
        "free -h",
        "sysctl kernel.randomize_va_space kernel.yama.ptrace_scope "
        "kernel.kptr_restrict kernel.dmesg_restrict net.ipv4.ip_forward",
        "aa-status",
    ],
    "Users, auth & access": [
        "cat /etc/passwd",
        "cat /etc/group",
        "getent passwd",
        "cat /etc/sudoers",
        "ls -la /etc/sudoers.d",
        "sshd -T",
        "last -n 50",
        "lastb -n 30",
        "lastlog",
        "who",
    ],
    "Network & firewall": [
        "ss -tulpn",
        "ss -tan",
        "ip addr show",
        "ip route show",
        "iptables -S",
        "ip6tables -S",
        "nft list ruleset",
        "ufw status verbose",
        "resolvectl status",
    ],
    "Packages, services & persistence": [
        "dpkg-query -W",
        "apt list --upgradable",
        "systemctl list-units --type=service --state=running",
        "systemctl list-unit-files --state=enabled",
        "systemctl list-timers",
        "crontab -l",
        "cat /etc/crontab",
        "ls -la /etc/cron.d /etc/cron.daily /etc/cron.hourly "
        "/etc/cron.weekly /etc/cron.monthly",
        "find / -xdev -perm -4000 -type f",
        "find / -xdev -perm -2000 -type f",
        "find / -xdev -perm -0002 -type f",
    ],
}
