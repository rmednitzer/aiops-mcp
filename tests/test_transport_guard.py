"""SEC-7 / invariant 7: stdio default; HTTP needs token + non-loopback opt-in; SSRF filter."""

from __future__ import annotations

import pytest

from praxis._ssrf import (
    SSRFBlocked,
    assert_egress_allowed,
    is_blocked_address,
    resolve_and_assert_egress_allowed,
)
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


def test_http_host_whitespace_is_stripped() -> None:
    # A stray-whitespace loopback host is still recognised as loopback, not treated
    # as a non-loopback bind that would demand the opt-in (BL-060).
    cfg = load_config({"PRAXIS_HTTP_HOST": " 127.0.0.1\n"})
    assert cfg.http_host == "127.0.0.1"
    assert cfg.http_is_loopback is True
    # A whitespace-only host defaults to loopback (the safest bind), never empty.
    assert load_config({"PRAXIS_HTTP_HOST": "   "}).http_host == "127.0.0.1"


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


def test_ssrf_blocks_ipv4_embedded_in_ipv6() -> None:
    # IPv4-in-IPv6 embeddings must not smuggle a blocked v4 range past the
    # filter: v4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96, RFC 6052), and
    # 6to4 (2002::/16) forms of loopback, RFC1918, and the IMDS address
    # (BL-061 bypass sweep).
    embedded = [
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::7f00:1",  # NAT64(127.0.0.1)
        "64:ff9b::a00:1",  # NAT64(10.0.0.1)
        "2002:7f00:1::",  # 6to4 from 127.0.0.1
        "2002:a00:1::",  # 6to4 from 10.0.0.1
    ]
    for host in embedded:
        assert is_blocked_address(host) is True, host
    # A public v6 literal is still allowed (no over-blocking).
    assert is_blocked_address("2001:4860:4860::8888") is False


def test_ssrf_blocks_ipv6_special_ranges_and_sixtofour_relay() -> None:
    # ULA, multicast, unspecified, and the deprecated 6to4 relay anycast
    # (192.88.99.0/24, RFC 7526): never legitimate praxis egress (BL-096).
    hosts = [
        "fc00::1",
        "fd12:3456::1",
        "ff02::1",
        "::",
        "0.0.0.0",  # noqa: S104 - asserting the filter BLOCKS the all-interfaces literal
        "192.88.99.1",
    ]
    for host in hosts:
        assert is_blocked_address(host) is True, host


def test_assert_egress_blocks_userinfo_and_bracketed_v6_tricks() -> None:
    # The URL host is what urlparse reports as hostname: a public-looking
    # userinfo prefix must not mask a blocked host, and bracketed v6 literals
    # are normalised before classification.
    for url in [
        "http://8.8.8.8@127.0.0.1/",  # userinfo trick: real host is loopback
        "http://[::ffff:169.254.169.254]/latest/",
        "http://[fe80::1]:8080/",
    ]:
        with pytest.raises(SSRFBlocked):
            assert_egress_allowed(url)
    assert_egress_allowed("https://[2001:4860:4860::8888]/resolve")  # public v6: allowed


def test_resolve_egress_allows_public_name_and_returns_pinned_ip() -> None:
    # A name that resolves to a public address is allowed; the vetted IP is returned
    # so the caller pins the connection to it (no re-resolution before connect).
    ips = resolve_and_assert_egress_allowed(
        "https://example.com/path", resolver=lambda n: ["93.184.216.34"]
    )
    assert ips == ["93.184.216.34"]


def test_resolve_egress_blocks_rebinding_to_private() -> None:
    # DNS rebinding: a public-looking name that resolves into the fleet is refused.
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed(
            "http://evil.example/", resolver=lambda n: ["169.254.169.254"]
        )
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed("http://evil2.example/", resolver=lambda n: ["::1"])


def test_resolve_egress_checks_every_resolved_ip() -> None:
    # A multi-record answer with one public and one private address is refused:
    # every resolved IP is checked, not just the first (the round-robin rebinding trick).
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed(
            "http://mix.example/", resolver=lambda n: ["8.8.8.8", "127.0.0.1"]
        )


def test_resolve_egress_fail_closed_on_unresolvable_or_empty() -> None:
    def nxdomain(n: str) -> list[str]:
        raise OSError("name or service not known")

    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed("http://nope.example/", resolver=nxdomain)
    with pytest.raises(SSRFBlocked):  # resolves to nothing
        resolve_and_assert_egress_allowed("http://empty.example/", resolver=lambda n: [])


def test_resolve_egress_fail_closed_on_unparseable_address() -> None:
    # A resolver returning a non-IP string is refused, never waved through.
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed(
            "http://weird.example/", resolver=lambda n: ["not-an-ip"]
        )


def test_resolve_egress_ip_literal_skips_resolution() -> None:
    # An IP literal is checked directly; the resolver is never consulted.
    calls: list[str] = []

    def spy(n: str) -> list[str]:
        calls.append(n)
        return ["127.0.0.1"]

    assert resolve_and_assert_egress_allowed("https://8.8.8.8/r", resolver=spy) == ["8.8.8.8"]
    assert calls == []
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed("http://169.254.169.254/", resolver=spy)


def test_resolve_egress_uses_urlparse_host_not_userinfo() -> None:
    # The resolved host is urlparse's hostname, so a public-looking userinfo prefix
    # cannot mask a name that rebinds into the fleet.
    with pytest.raises(SSRFBlocked):
        resolve_and_assert_egress_allowed(
            "http://8.8.8.8@evil.example/", resolver=lambda n: ["127.0.0.1"]
        )
