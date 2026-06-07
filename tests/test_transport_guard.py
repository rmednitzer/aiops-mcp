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
