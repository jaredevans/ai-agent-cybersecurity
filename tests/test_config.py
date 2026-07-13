import os

from agent.config import load_env_file


def test_load_env_file_sets_new_vars(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text('FOO_TEST_VAR="bar"\n# comment\nBAZ=qux\n')
    monkeypatch.delenv("FOO_TEST_VAR", raising=False)
    monkeypatch.delenv("BAZ", raising=False)

    loaded = load_env_file(env)

    assert set(loaded) == {"FOO_TEST_VAR", "BAZ"}
    assert os.environ["FOO_TEST_VAR"] == "bar"
    assert os.environ["BAZ"] == "qux"


def test_load_env_file_does_not_override_existing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("ALREADY_SET=fromfile\n")
    monkeypatch.setenv("ALREADY_SET", "fromenv")

    loaded = load_env_file(env)

    assert "ALREADY_SET" not in loaded
    assert os.environ["ALREADY_SET"] == "fromenv"


def test_load_env_file_missing_is_noop(tmp_path):
    assert load_env_file(tmp_path / "nope.env") == []
