"""SSRF egress filter (ADR-0006; SEC-7).

Any server-initiated request (a cloud API call, a webhook) must pass through this
filter so the MCP surface cannot be used to pivot into the private fleet network.
Loopback, link-local, private (RFC1918), CGNAT (100.64.0.0/10), unique-local,
multicast, reserved, unspecified, and the deprecated 6to4 relay anycast
(192.88.99.0/24, RFC 7526) are blocked. IPv4 embedded in IPv6 (v4-mapped
::ffff:0:0/96, NAT64 64:ff9b::/96, 6to4 2002::/16) is covered by the standard
registry data the ``ipaddress`` module carries on the supported interpreters.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
# The deprecated 6to4 relay anycast (RFC 7526): egress here relays into 2002::/16
# and is never a legitimate praxis destination. Blocked explicitly because the
# interpreter registry data for this range varies across patch versions.
_SIXTOFOUR_RELAY_V4 = ipaddress.ip_network("192.88.99.0/24")
_BLOCKED_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

_IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class SSRFBlocked(Exception):
    """Raised when an egress target resolves to a blocked range."""


def _as_ip(name: str) -> _IPAddress | None:
    """Parse ``name`` as an IP literal in any common encoding, else None.

    Covers dotted-quad and IPv6, plus the legacy and obfuscated IPv4 forms an
    attacker reaches for to dodge a naive string check: a bare 32-bit integer
    (decimal, ``0x`` hex, or ``0`` octal), the short dotted forms (``127.1``),
    and a single trailing dot (``127.0.0.1.``). ``inet_aton`` canonicalises the
    numeric and short forms the same way the C resolver would, so an encoded
    loopback or link-local address is recognised, not waved through. Returns
    None for a genuine DNS name (decided, fail-closed, by the caller).
    """
    candidate = name.rstrip(".")
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(candidate))
    except (OSError, ValueError):
        return None


def _ip_is_blocked(ip: _IPAddress) -> bool:
    if ip.version == 4 and (ip in _CGNAT_V4 or ip in _SIXTOFOUR_RELAY_V4):
        return True
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_blocked_address(host: str) -> bool:
    """True if ``host`` must be blocked.

    Accepts an IP literal in any encoding (see ``_as_ip``) or a known-local
    name. A bare DNS name returns False here; the egress decision for names is
    made, fail-closed, by ``assert_egress_allowed`` (this predicate classifies
    literals, it does not resolve names).
    """
    name = host.strip().strip("[]").lower()
    if name in _BLOCKED_NAMES:
        return True
    ip = _as_ip(name)
    if ip is None:
        return False
    return _ip_is_blocked(ip)


def assert_egress_allowed(url: str) -> None:
    """Raise SSRFBlocked unless the URL's host is a verifiably public IP literal.

    Fail-closed (SEC-7, invariant 7). A blocked-range IP in any encoding is
    refused, and so is a bare DNS name: v0 does not resolve names, and an
    unresolved name cannot be proven to point outside the private fleet, so a
    name is the easiest SSRF pivot and is denied rather than waved through. A
    caller that must reach a named host resolves it itself and passes the
    public IP literal.
    """
    parsed = urlparse(url if "://" in url else f"//{url}")
    host = parsed.hostname or ""
    name = host.strip().strip("[]").lower()
    if not name:
        raise SSRFBlocked(f"egress to {url!r} is blocked: no host")
    if name in _BLOCKED_NAMES:
        raise SSRFBlocked(f"egress to {host!r} is blocked by the SSRF filter")
    ip = _as_ip(name)
    if ip is None:
        raise SSRFBlocked(
            f"egress to hostname {host!r} is blocked: v0 does not resolve names; "
            "pass a public IP literal"
        )
    if _ip_is_blocked(ip):
        raise SSRFBlocked(f"egress to {host!r} is blocked by the SSRF filter")
