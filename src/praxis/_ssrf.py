"""SSRF egress filter (ADR-0006; SEC-7).

Any server-initiated request (a cloud API call, a webhook) must pass through this
filter so the MCP surface cannot be used to pivot into the private fleet network.
Loopback, link-local, private (RFC1918), CGNAT (100.64/10), unique-local,
multicast, reserved, and unspecified addresses are blocked.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")
_BLOCKED_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


class SSRFBlocked(Exception):
    """Raised when an egress target resolves to a blocked range."""


def is_blocked_address(host: str) -> bool:
    """True if ``host`` (an IP literal or a known-local name) must be blocked."""
    name = host.strip().strip("[]").lower()
    if name in _BLOCKED_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        # A hostname that is not an IP literal: name-based resolution is out of
        # scope for v0; only IP literals and known-local names are decided here.
        return False
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    return bool(
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_egress_allowed(url: str) -> None:
    """Raise SSRFBlocked if the URL's host is in a blocked range."""
    parsed = urlparse(url if "://" in url else f"//{url}")
    host = parsed.hostname or ""
    if not host or is_blocked_address(host):
        raise SSRFBlocked(f"egress to {host or url!r} is blocked by the SSRF filter")
