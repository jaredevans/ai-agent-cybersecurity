from agent.collect import collect_baseline, CollectionResult


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_collect_runs_allowed_and_skips_rejected():
    checklist = {"Cat A": ["uname -a", "rm -rf /"]}
    ran = []

    def fake_runner(cmd, **kwargs):
        ran.append(cmd)
        return FakeCompleted(0, "Linux host\n", "")

    results = collect_baseline("ia", checklist, runner=fake_runner)

    assert [r.command for r in results] == ["uname -a", "rm -rf /"]
    # allowed command executed and captured
    assert results[0].allowed is True
    assert results[0].category == "Cat A"
    assert results[0].exit_code == 0
    assert "Linux host" in results[0].stdout
    # rejected command never ran
    assert results[1].allowed is False
    assert results[1].exit_code is None
    assert len(ran) == 1  # only the allowed command reached SSH


def test_collect_audits_every_command():
    checklist = {"Cat A": ["uname -a", "rm -rf /"]}
    records = []

    def fake_runner(cmd, **kwargs):
        return FakeCompleted(0, "ok\n", "")

    collect_baseline("ia", checklist, runner=fake_runner,
                     audit=records.append)

    assert len(records) == 2
    assert records[0]["command"] == "uname -a"
    assert records[0]["decision"] == "allowed"
    assert records[0]["category"] == "Cat A"
    assert records[1]["command"] == "rm -rf /"
    assert records[1]["decision"] in {"blocked"}
    assert records[1]["executed"] is False


def test_collect_captures_transport_error_without_raising():
    checklist = {"Cat A": ["uname -a"]}

    def boom(cmd, **kwargs):
        raise OSError("ssh exploded")

    results = collect_baseline("ia", checklist, runner=boom)

    assert results[0].allowed is True
    assert results[0].exit_code is None
    assert "ssh exploded" in results[0].stderr


def test_collect_audits_transport_error_with_message():
    checklist = {"Cat A": ["uname -a"]}
    records = []

    def boom(cmd, **kwargs):
        raise OSError("ssh exploded")

    collect_baseline("ia", checklist, runner=boom, audit=records.append)

    assert len(records) == 1
    assert records[0]["executed"] is False
    assert records[0]["exit_code"] is None
    assert "ssh exploded" in records[0]["error"]


def test_collect_prefixes_sudo_when_enabled():
    checklist = {"Cat A": ["cat /etc/shadow"]}
    seen = []

    def fake_runner(cmd, **kwargs):
        seen.append(cmd)
        return FakeCompleted(0, "root:*:...\n", "")

    results = collect_baseline("ia", checklist, runner=fake_runner, sudo=True)

    assert results[0].allowed is True
    assert results[0].command == "sudo cat /etc/shadow"
    # guard rewrote it to `sudo -n cat /etc/shadow`; run_ssh joins the argv.
    assert seen[0][-1] == "sudo -n cat /etc/shadow"


def test_collect_no_sudo_prefix_by_default():
    checklist = {"Cat A": ["cat /etc/shadow"]}
    seen = []

    def fake_runner(cmd, **kwargs):
        seen.append(cmd)
        return FakeCompleted(0, "", "")

    results = collect_baseline("ia", checklist, runner=fake_runner)

    assert results[0].command == "cat /etc/shadow"
    assert seen[0][-1] == "cat /etc/shadow"


def test_collect_sudo_rejection_still_skipped():
    # A write command stays blocked even with the sudo prefix.
    checklist = {"Cat A": ["rm -rf /"]}
    ran = []

    def fake_runner(cmd, **kwargs):
        ran.append(cmd)
        return FakeCompleted(0, "", "")

    results = collect_baseline("ia", checklist, runner=fake_runner, sudo=True)

    assert results[0].allowed is False
    assert len(ran) == 0


def test_collect_passes_parsed_argv_to_ssh():
    checklist = {"Cat A": ["grep -n root /etc/passwd"]}
    seen = []

    def fake_runner(cmd, **kwargs):
        seen.append(cmd)
        return FakeCompleted(0, "", "")

    collect_baseline("ia", checklist, runner=fake_runner)

    # run_ssh joins the guard-parsed argv; a raw-string bug would mangle this.
    # (host and remote command are the last two argv elements; mux -o args first.)
    assert seen[0][0] == "ssh"
    assert seen[0][-2] == "ia"
    assert seen[0][-1] == "grep -n root /etc/passwd"
