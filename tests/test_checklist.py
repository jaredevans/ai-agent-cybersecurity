from agent.checklist import CHECKLIST
from agent.guard import check_command


def test_checklist_has_all_four_categories():
    assert set(CHECKLIST.keys()) == {
        "System & kernel",
        "Users, auth & access",
        "Network & firewall",
        "Packages, services & persistence",
    }


def test_every_baseline_command_is_guard_allowed():
    offenders = []
    for category, commands in CHECKLIST.items():
        for command in commands:
            if not check_command(command).allowed:
                offenders.append((category, command))
    assert offenders == [], f"guard-rejected baseline commands: {offenders}"
