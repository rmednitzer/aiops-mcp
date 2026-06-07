"""SEC-9: secrets are redacted from audited parameters and error strings."""

from __future__ import annotations

from praxis.execution.redaction import REDACTED, redact, redact_args


def test_secrets_redacted() -> None:
    args: dict[str, object] = {
        "host": "axiom",
        "password": "hunter2",
        "nested": {"api_key": "AKIAIOSFODNN7EXAMPLE"},
        "items": ["token=xyzsupersecret", "plain"],
    }
    out = redact_args(args)
    assert out["host"] == "axiom"
    assert out["password"] == REDACTED
    nested = out["nested"]
    assert isinstance(nested, dict)
    assert nested["api_key"] == REDACTED
    assert "xyzsupersecret" not in str(out["items"])


def test_inline_value_shapes_redacted() -> None:
    assert "AKIAIOSFODNN7EXAMPLE" not in redact("creds AKIAIOSFODNN7EXAMPLE end")
    assert "hunter2" not in redact("password=hunter2")
    assert "ghp_" not in redact("ghp_0123456789abcdefghijABCDEFG")


def test_pem_block_redacted() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIsecretkeymaterial\n-----END RSA PRIVATE KEY-----"
    redacted = redact(pem)
    assert "secretkeymaterial" not in redacted


def test_credential_flags_and_urls_redacted() -> None:
    # A space-separated CLI flag keeps the flag name but redacts the value (BL-041).
    out = redact("mysql --password hunter2here --host db")
    assert "hunter2here" not in out
    assert "--password" in out
    # The equals form: the secret is gone.
    assert "abc123secret" not in redact("--token=abc123secret")
    # Credentials embedded in a DSN/URL: user and host survive, the password does not.
    dsn = redact("postgres://user:secretpw@dbhost:5432/app")
    assert "secretpw" not in dsn
    assert "user" in dsn and "dbhost" in dsn
    # A bearer token, including the three-part "Authorization: Bearer <tok>" form.
    assert "realtok" not in redact("Authorization: Bearer realtok.value.here")
    assert "barevalue" not in redact("Bearer barevalue")


def test_non_secret_passthrough() -> None:
    assert redact("just a normal line") == "just a normal line"
    out = redact_args({"count": 3, "flag": True})
    assert out == {"count": 3, "flag": True}
