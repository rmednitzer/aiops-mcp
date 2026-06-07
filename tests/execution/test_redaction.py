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
    # A DSN password may itself contain colons; the whole secret is still redacted.
    colon_dsn = redact("postgres://user:pa:ss:word@dbhost/db")
    assert "pa:ss:word" not in colon_dsn
    assert "word" not in colon_dsn  # the password tail does not survive
    assert "dbhost" in colon_dsn
    # A bearer token, including the three-part "Authorization: Bearer <tok>" form.
    assert "realtok" not in redact("Authorization: Bearer realtok.value.here")
    assert "barevalue" not in redact("Bearer barevalue")


def test_provider_token_shapes_redacted() -> None:
    # Structurally-anchored provider secret shapes are redacted even bare (not behind
    # a key), so a raw command carrying one does not reach the audit log. Each sample
    # is assembled from fragments so this source file never contains a contiguous
    # token literal (which secret scanning would flag); the redactor sees the full
    # string only at runtime.
    body = "A1b2C3d4E5f6G7h8I9j0KLMN"  # 24 placeholder chars, clearly not a real secret
    cases = [
        "github_" + "pat_" + body + "OPQRstuvwx",
        "gl" + "pat-" + body,
        "AIza" + body + "OPQRstuvwxyz123",
        "sk-" + "proj-" + body,
        "rk_" + "live_" + body,
    ]
    for secret in cases:
        assert secret not in redact(f"value {secret} trailing"), secret


def test_authorization_value_fully_redacted_including_sigv4() -> None:
    # The whole header value is redacted to end-of-line, so a comma-separated SigV4
    # credential cannot leak its Signature field while only the access-key id is hit.
    line = (
        "Authorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/x, "
        "SignedHeaders=host, Signature=deadbeefcafef00dba5eba11c0ffee99"
    )
    out = redact(line)
    assert "deadbeefcafef00dba5eba11c0ffee99" not in out
    assert "Authorization" in out  # the header name is preserved as context


def test_non_secret_passthrough() -> None:
    assert redact("just a normal line") == "just a normal line"
    out = redact_args({"count": 3, "flag": True})
    assert out == {"count": 3, "flag": True}
