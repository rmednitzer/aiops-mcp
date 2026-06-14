"""SSRF egress filter (ADR-0006; SEC-7).

Any server-initiated request (a cloud API call, a webhook) must pass through this
filter so the MCP surface cannot be used to pivot into the private fleet network.
Loopback, link-local, private (RFC1918), CGNAT (100.64.0.0/10), unique-local,
multicast, reserved, unspecified, and the deprecated 6to4 relay anycast
(192.88.99.0/24, RFC 7526) are blocked. IPv4 embedded in IPv6 (v4-mapped
::ffff:0:0/96, NAT64 64:ff9b::/96, 6to4 2002::/16) is covered by the standard
registry data the ``ipaddress`` module carries on the supported interpreters.

Two egress entry points (BL-046): ``assert_egress_allowed`` is the strict default
that refuses a bare DNS name (a name cannot be proven public without resolving it);
``resolve_and_assert_egress_allowed`` is the rebinding-aware variant that resolves a
name once, checks every resolved address, and returns the vetted IP literals so the
caller pins the connection to exactly the addresses checked here.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable, Iterable
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


def _normalized_host(url: str) -> str:
    """The lowercased, de-bracketed hostname of ``url`` (no scheme, userinfo, or port)."""
    parsed = urlparse(url if "://" in url else f"//{url}")
    return (parsed.hostname or "").strip().strip("[]").lower()


def assert_egress_allowed(url: str) -> None:
    """Raise SSRFBlocked unless the URL's host is a verifiably public IP literal.

    Fail-closed (SEC-7, invariant 7). A blocked-range IP in any encoding is
    refused, and so is a bare DNS name: this strict variant does not resolve
    names, and an unresolved name cannot be proven to point outside the private
    fleet, so a name is the easiest SSRF pivot and is denied rather than waved
    through. A caller that must reach a named host uses
    ``resolve_and_assert_egress_allowed`` (which resolves and pins) or passes a
    public IP literal.
    """
    name = _normalized_host(url)
    if not name:
        raise SSRFBlocked(f"egress to {url!r} is blocked: no host")
    if name in _BLOCKED_NAMES:
        raise SSRFBlocked(f"egress to {name!r} is blocked by the SSRF filter")
    ip = _as_ip(name)
    if ip is None:
        raise SSRFBlocked(
            f"egress to hostname {name!r} is blocked: the strict filter does not resolve "
            "names; pass a public IP literal or use resolve_and_assert_egress_allowed"
        )
    if _ip_is_blocked(ip):
        raise SSRFBlocked(f"egress to {name!r} is blocked by the SSRF filter")


def _default_resolver(name: str) -> list[str]:
    """Resolve ``name`` to its addresses via the system resolver (A and AAAA records)."""
    infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def resolve_and_assert_egress_allowed(
    url: str, *, resolver: Callable[[str], Iterable[str]] | None = None
) -> list[str]:
    """Resolve the URL's host and return the vetted public IPs, or raise SSRFBlocked.

    Rebinding-aware (SEC-7, invariant 7, BL-046). Unlike ``assert_egress_allowed``,
    which refuses a bare name, this resolves the host once, checks EVERY resolved
    address against the blocked ranges, and returns the validated IP literals so the
    caller connects to exactly the addresses vetted here, never re-resolving between
    the check and the connect (the DNS-rebinding pin). Fail-closed: an unresolvable
    host, a host that resolves to nothing, an unparseable address, or any resolved
    address in a blocked range raises. An IP literal is checked directly without
    resolution. The ``resolver`` seam (default ``socket.getaddrinfo``) is injectable.
    """
    name = _normalized_host(url)
    if not name:
        raise SSRFBlocked(f"egress to {url!r} is blocked: no host")
    if name in _BLOCKED_NAMES:
        raise SSRFBlocked(f"egress to {name!r} is blocked by the SSRF filter")
    literal = _as_ip(name)
    if literal is not None:
        if _ip_is_blocked(literal):
            raise SSRFBlocked(f"egress to {name!r} is blocked by the SSRF filter")
        return [str(literal)]
    resolve = resolver if resolver is not None else _default_resolver
    try:
        addresses = list(resolve(name))
    except OSError as exc:
        raise SSRFBlocked(
            f"egress to {name!r} is blocked: the host does not resolve ({exc})"
        ) from exc
    vetted: list[str] = []
    seen: set[str] = set()
    for addr in addresses:
        ip = _as_ip(addr.split("%", 1)[0])
        if ip is None:
            raise SSRFBlocked(
                f"egress to {name!r} is blocked: unparseable resolved address {addr!r}"
            )
        if _ip_is_blocked(ip):
            raise SSRFBlocked(
                f"egress to {name!r} is blocked: it resolves to {ip}, a blocked range"
            )
        text = str(ip)
        if text not in seen:
            seen.add(text)
            vetted.append(text)
    if not vetted:
        raise SSRFBlocked(f"egress to {name!r} is blocked: the host resolved to no addresses")
    return vetted
