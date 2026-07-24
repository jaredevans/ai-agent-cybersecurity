from agent.privilege import detect_privilege, Privilege


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _runner_for(responses):
    """responses: list of FakeCompleted returned in call order."""
    calls = {"n": 0}

    def runner(cmd, **kwargs):
        r = responses[calls["n"]]
        calls["n"] += 1
        return r

    return runner


def test_root_user_detected_without_sudo_probe():
    # id -u returns 0 -> root; no second call needed.
    runner = _runner_for([FakeCompleted(0, "0\n")])
    priv = detect_privilege("ia", runner=runner)
    assert priv == Privilege(is_root=True, has_sudo=False)
    assert priv.use_sudo is False


def test_non_root_with_passwordless_sudo():
    # id -u -> 1000, then sudo -n id -u -> 0.
    runner = _runner_for([FakeCompleted(0, "1000\n"), FakeCompleted(0, "0\n")])
    priv = detect_privilege("ia", runner=runner)
    assert priv == Privilege(is_root=False, has_sudo=True)
    assert priv.use_sudo is True


def test_non_root_without_sudo():
    # id -u -> 1000, then sudo -n id -u -> nonzero (password required / denied).
    runner = _runner_for([FakeCompleted(0, "1000\n"),
                          FakeCompleted(1, "", "sudo: a password is required")])
    priv = detect_privilege("ia", runner=runner)
    assert priv.use_sudo is False


def test_transport_error_falls_back_to_no_sudo():
    def boom(cmd, **kwargs):
        raise OSError("ssh exploded")

    priv = detect_privilege("ia", runner=boom)
    assert priv == Privilege(is_root=False, has_sudo=False)
    assert priv.use_sudo is False
