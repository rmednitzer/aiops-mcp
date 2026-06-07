"""SEC-7 / invariant 7: stdio default; HTTP needs token + non-loopback opt-in; SSRF filter."""

from __future__ import annotations

import pytest

from praxis._ssrf import SSRFBlocked, assert_egress_allowed, is_blocked_address
from praxis.config import Config, TransportError, load_config, validate_transport
from praxis.execution.policy import Mode


def test_stdio_is_always_allowed() -> None:
    validate_transport(Config(transport="stdio"))  # no raise


def test_http_refuses_without_token() -> None:
    with pytest.raises(TransportError):
        validate_transport(Config(transport="http", http_token=None, http_host="127.0.0.1"))


def test_http_refuses_nonloopback_without_optin() -> None:
    with pytest.raises(TransportError):
        validate_transport(
            Config(transport="http", http_token="t", http_host="0.0.0.0", allow_any=False)  # noqa: S104
        )


def test_http_loopback_with_token_ok() -> None:
    validate_transport(Config(transport="http", http_token="t", http_host="127.0.0.1"))


def test_http_nonloopback_requires_both_token_and_optin() -> None:
    validate_transport(
        Config(transport="http", http_token="t", http_host="0.0.0.0", allow_any=True)  # noqa: S104
    )


def test_load_config_http_defaults_restricted_off() -> None:
    cfg = load_config({"PRAXIS_TRANSPORT": "http", "PRAXIS_HTTP_TOKEN": "x", "PRAXIS_MODE": "open"})
    assert cfg.transport == "http"
    assert cfg.http_token == "x"
    assert cfg.mode is Mode.OPEN
    assert cfg.allow_restricted is False  # default-deny restricted over HTTP


def test_nonnumeric_port_degrades_to_default_not_raise() -> None:
    # A bad PRAXIS_HTTP_PORT must not raise at import time and bypass the fail-closed
    # transport path; it falls back to the default and is validated later.
    cfg = load_config({"PRAXIS_HTTP_PORT": "not-a-port"})
    assert cfg.http_port == 8765


def test_http_rejects_out_of_range_port() -> None:
    with pytest.raises(TransportError):
        validate_transport(Config(transport="http", http_token="t", http_port=70000))
    with pytest.raises(TransportError):
        validate_transport(Config(transport="http", http_token="t", http_port=0))


def test_ssrf_blocks_private_ranges() -> None:
    blocked = [
        "127.0.0.1",
        "169.254.169.254",  # cloud metadata
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",  # CGNAT
        "::1",
        "fe80::1",
        "localhost",
    ]
    for host in blocked:
        assert is_blocked_address(host) is True, host
    for host in ["8.8.8.8", "1.1.1.1", "93.184.216.34"]:
        assert is_blocked_address(host) is False, host


def test_assert_egress_allowed_raises_on_metadata() -> None:
    with pytest.raises(SSRFBlocked):
        assert_egress_allowed("http://169.254.169.254/latest/meta-data/")
    assert_egress_allowed("https://8.8.8.8/resolve")  # no raise


def test_ssrf_blocks_obfuscated_ip_encodings() -> None:
    # Decimal, hex, octal, short-dotted, and trailing-dot encodings of a blocked IP
    # all canonicalise to the loopback/unspecified range (BL-042).
    for host in ["2130706433", "0x7f000001", "0177.0.0.1", "127.1", "127.0.0.1.", "0"]:
        assert is_blocked_address(host) is True, host
    # The decimal encoding of a public IP is still allowed (no over-blocking).
    assert is_blocked_address("134744072") is False  # 8.8.8.8


def test_assert_egress_is_fail_closed_on_names_and_encodings() -> None:
    # Fail-closed: an obfuscated loopback, a metadata name, and any unresolvable name
    # are all refused; only a verifiably public IP literal is allowed (BL-042).
    for url in [
        "http://metadata.google.internal/latest/",
        "http://2130706433/",
        "http://example.com",
    ]:
        with pytest.raises(SSRFBlocked):
            assert_egress_allowed(url)
    assert_egress_allowed("https://8.8.8.8/resolve")  # public IP literal: allowed
