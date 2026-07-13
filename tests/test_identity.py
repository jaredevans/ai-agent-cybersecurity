from agent.identity import discover_self_hosts


class FakeCompleted:
    def __init__(self, returncode, stdout, stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_discover_parses_ips_and_names():
    outputs = {
        "hostname -I": "192.168.1.10 10.0.0.5 \n",
        "hostname -f": "web.example.com\n",
        "hostname": "web\n",
    }

    def fake_runner(cmd, **kwargs):
        remote = cmd[-1]
        return FakeCompleted(0, outputs.get(remote, ""))

    hosts = discover_self_hosts("ia", runner=fake_runner)
    assert "192.168.1.10" in hosts
    assert "10.0.0.5" in hosts
    assert "web.example.com" in hosts
    assert "web" in hosts


def test_discover_excludes_reverse_dns():
    # `hostname -A` (reverse DNS) is not queried, so PTR names never widen curl.
    called = []

    def fake_runner(cmd, **kwargs):
        called.append(cmd[-1])
        return FakeCompleted(0, "web\n")

    discover_self_hosts("ia", runner=fake_runner)
    assert "hostname -A" not in called


def test_discover_skips_failures():
    def fake_runner(cmd, **kwargs):
        raise OSError("unreachable")

    assert discover_self_hosts("ia", runner=fake_runner) == frozenset()


def test_discover_includes_etc_hosts_self_names():
    outputs = {
        "hostname -I": "10.211.55.3 \n",
        "hostname -f": "ialocal\n",
        "hostname": "ialocal\n",
        "cat /etc/hosts": (
            "127.0.0.1 localhost\n"
            "127.0.1.1 ialocal\n"
            "10.211.55.3 test.ialocal.com\n"      # maps to a self IP -> include
            "8.8.8.8 evil.example.com\n"          # NOT self -> exclude
            "# a comment\n"
        ),
    }

    def fake_runner(cmd, **kwargs):
        return FakeCompleted(0, outputs.get(cmd[-1], ""))

    hosts = discover_self_hosts("ia", runner=fake_runner)
    assert "test.ialocal.com" in hosts        # /etc/hosts self-mapped name
    assert "localhost" in hosts               # loopback
    assert "10.211.55.3" in hosts             # own IP
    assert "evil.example.com" not in hosts    # maps to a non-self IP
