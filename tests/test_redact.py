from agent.redact import redact, redact_secret


# --- redact_secret format ---------------------------------------------------
def test_redact_secret_keeps_first_two_and_last_two():
    assert redact_secret("AKIAIOSFODNN7EXAMPLE") == "AK...LE"


def test_redact_secret_fully_masks_short_values():
    assert redact_secret("hunter2") == "[redacted]"
    assert redact_secret("12345678") == "[redacted]"  # boundary: <= 8


# --- private keys -----------------------------------------------------------
def test_private_key_body_is_removed_markers_kept():
    text = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n"
        "SECRETKEYMATERIALdeadbeefdeadbeefdeadbeef\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    out = redact(text)
    assert "BEGIN OPENSSH PRIVATE KEY" in out       # presence still visible
    assert "END OPENSSH PRIVATE KEY" in out
    assert "[redacted private key]" in out
    assert "SECRETKEYMATERIAL" not in out
    assert "b3BlbnNzaC1rZXk" not in out


# --- shadow hashes ----------------------------------------------------------
def test_shadow_hash_redacted_algorithm_prefix_kept():
    line = "root:$6$abcdef0123456789$Zx9yLongHashValueHereABCDEFXYZ0123456789:19876:0:99999:7:::"
    out = redact(line)
    assert out.startswith("root:$6$")            # algorithm preserved (a finding)
    assert "Zx9yLongHashValueHere" not in out    # salt+hash gone
    assert out.endswith(":19876:0:99999:7:::")   # trailing fields intact


def test_passwd_line_untouched():
    line = "root:x:0:0:root:/root:/bin/bash"
    assert redact(line) == line  # field 2 is `x`, not a hash


def test_locked_account_untouched():
    line = "daemon:*:19000:0:99999:7:::"
    assert redact(line) == line  # `*` is not a hash


# --- redis auth directives --------------------------------------------------
def test_requirepass_config_line_redacted():
    out = redact("requirepass SuperSecretRedisPassword123")
    assert "SuperSecretRedisPassword123" not in out
    assert out == "requirepass Su...23"


def test_requirepass_config_get_two_line_form_redacted():
    # `redis-cli CONFIG GET requirepass` output: key on one line, value on next.
    out = redact("requirepass\nSuperSecretRedisPassword123\n")
    lines = out.split("\n")
    assert lines[0] == "requirepass"
    assert lines[1] == "Su...23"


def test_requirepass_empty_value_untouched():
    # No password set -> empty value line stays empty (itself a finding).
    out = redact("requirepass\n\n")
    assert out == "requirepass\n\n"


# --- no false positives on security-relevant non-secrets --------------------
def test_password_authentication_directive_survives():
    line = "PasswordAuthentication yes"
    assert redact(line) == line


def test_password_encryption_method_survives():
    line = "password_encryption = scram-sha-256"
    assert redact(line) == line


def test_plain_text_unchanged():
    text = "Linux ia 6.8.0-31-generic x86_64\nActive: active (running)\n"
    assert redact(text) == text


def test_redact_is_idempotent():
    text = "root:$6$salt$LongHashValueABCDEF0123456789:19876:0:99999:7:::"
    assert redact(redact(text)) == redact(text)


# --- KEY=VALUE secrets (docker inspect Env, .env, compose, systemd) ---------
def test_docker_inspect_env_password_redacted():
    # The exact shape docker inspect emits (JSON array of NAME=VALUE strings).
    text = '    "Env": [\n        "POSTGRES_PASSWORD=mushmush",\n        "PG_VERSION=18.3"\n    ]'
    out = redact(text)
    assert "mushmush" not in out
    assert 'POSTGRES_PASSWORD=[redacted]' in out
    assert "PG_VERSION=18.3" in out  # non-secret assignment untouched


def test_pgadmin_default_password_redacted():
    out = redact("PGADMIN_DEFAULT_PASSWORD=mushmush")
    assert out == "PGADMIN_DEFAULT_PASSWORD=[redacted]"


def test_env_file_secrets_redacted():
    # A typical .env file.
    env = (
        "# app config\n"
        "DEBUG=true\n"
        "MYSQL_ROOT_PASSWORD=r00tPassphrase!!\n"
        "DJANGO_SECRET_KEY=abcdef0123456789xyz\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7EXAMPLEKEY\n"
        "API_TOKEN=sk-abc123def456ghi789\n"
    )
    out = redact(env)
    assert "DEBUG=true" in out                                   # non-secret kept
    assert "r00tPassphrase!!" not in out
    assert "MYSQL_ROOT_PASSWORD=r0...!!" in out                  # first2...last2
    assert "abcdef0123456789xyz" not in out
    assert "wJalrXUtnFEMIK7EXAMPLEKEY" not in out
    assert "sk-abc123def456ghi789" not in out


def test_long_value_keeps_first_two_last_two():
    out = redact("POSTGRES_PASSWORD=SuperLongSecretValue99")
    assert out == "POSTGRES_PASSWORD=Su...99"


def test_quoted_env_value_redacted_quotes_preserved():
    assert redact('POSTGRES_PASSWORD="mushmush"') == 'POSTGRES_PASSWORD="[redacted]"'
    assert redact("DB_PASS: mushmush") == "DB_PASS: [redacted]"  # yaml-style


# --- URL-embedded credentials -----------------------------------------------
def test_database_url_password_redacted():
    out = redact("DATABASE_URL=postgres://appuser:s3cretDbPassw0rd@db.internal:5432/app")
    assert "s3cretDbPassw0rd" not in out             # password gone
    assert out == "DATABASE_URL=postgres://appuser:s3...rd@db.internal:5432/app"


def test_redis_url_without_user_redacted():
    out = redact("REDIS_URL=redis://:mySecretPw@127.0.0.1:6379/0")
    assert "mySecretPw" not in out
    assert "redis://:" in out and "@127.0.0.1:6379/0" in out


# --- no false positives on security-relevant non-secrets --------------------
def test_password_encryption_assignment_survives():
    # postgresql.conf: a finding (weak algo), NOT a secret. Must not be mangled.
    assert redact("password_encryption = scram-sha-256") == "password_encryption = scram-sha-256"


def test_midword_pass_not_matched():
    for line in ["COMPASS=north", "BYPASS=true", "PWD=/root/work", "PATH=/usr/bin:/bin"]:
        assert redact(line) == line


def test_env_redaction_idempotent():
    text = "POSTGRES_PASSWORD=mushmush\nAPI_TOKEN=sk-abc123def456ghi789"
    assert redact(redact(text)) == redact(text)


# --- bare/free-form PASSWORD=value ------------------------------------------
def test_bare_password_assignment_redacted():
    assert redact("PASSWORD=xyz") == "PASSWORD=[redacted]"
    assert redact("password=xyz") == "password=[redacted]"
    assert redact("PASSWORD=SuperLongPassword123") == "PASSWORD=Su...23"


# --- .pgpass lines ----------------------------------------------------------
def test_pgpass_line_password_redacted():
    out = redact("localhost:5432:mydb:myuser:s3cretPgPassw0rd")
    assert out == "localhost:5432:mydb:myuser:s3...rd"


def test_pgpass_wildcards_and_ip():
    assert redact("*:*:*:postgres:shortpw") == "*:*:*:postgres:[redacted]"
    out = redact("10.0.0.5:5432:app:app_user:LongEnoughSecretHere")
    assert out == "10.0.0.5:5432:app:app_user:Lo...re"


def test_pgpass_password_with_colon_redacted_whole():
    # password may itself contain colons; the whole tail is the password.
    out = redact("db.example.com:5432:app:svc:pa:ss:wo:rd:value")
    assert out.startswith("db.example.com:5432:app:svc:")
    assert "pa:ss:wo:rd:value" not in out


def test_pgpass_detector_leaves_passwd_and_group_untouched():
    passwd = "root:x:0:0:root:/root:/bin/bash"
    group = "sudo:x:27:jared"
    assert redact(passwd) == passwd     # 7 fields, field 2 = x (not a port)
    assert redact(group) == group       # only 4 fields
    # a comment line in a .pgpass file (host field starts with '#') is left alone
    assert redact("#localhost:5432:db:user:pw") == "#localhost:5432:db:user:pw"
