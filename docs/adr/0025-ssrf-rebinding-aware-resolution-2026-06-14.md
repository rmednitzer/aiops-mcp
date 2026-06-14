# ADR-0025: Rebinding-aware SSRF egress resolution (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (resolves the egress-resolution half of BL-046, from ADR-0012)

## Context

The SSRF egress filter (`src/praxis/_ssrf.py`, SEC-7) classifies IP literals in
every common encoding but, by deliberate v0 design, refuses a bare DNS name:
`assert_egress_allowed` cannot prove a name points outside the private fleet without
resolving it, so it fails closed. BL-046 asks for the missing capability: resolve a
hostname, check every resolved address, and do so in a DNS-rebinding-aware way, then
wire it into the egress path.

The DNS-rebinding hazard is that a name can resolve to a public address when checked
and to a private one when later connected (or round-robin between the two). A
filter that resolves, checks, and then lets the caller re-resolve before connecting
is defeated. The check must therefore return the exact vetted addresses so the caller
connects to those and never re-resolves.

There is no server-initiated egress consumer in v0 (stdio transport only; the cloud
and redfish adapters are planned, ADR-0022), so there is nothing to wire the filter
into yet. The deliverable here is the rebinding-aware primitive, ready for that
consumer, without weakening the current posture.

## Decision

1. Add `resolve_and_assert_egress_allowed(url, *, resolver=...)` alongside the strict
   `assert_egress_allowed`, rather than changing the strict default. It resolves the
   host once, checks EVERY resolved address against the existing blocked-range
   predicate (`_ip_is_blocked`, which already covers loopback, link-local, RFC1918,
   CGNAT, ULA, multicast, reserved, unspecified, the 6to4 relay anycast, and the
   IPv4-in-IPv6 embeddings), and returns the validated IP literals so the caller pins
   the connection to exactly those addresses. An IP literal is checked directly with
   no resolution. The resolver is an injectable seam (default `socket.getaddrinfo`)
   for testing.

2. Keep the default deny-by-default. `assert_egress_allowed` still refuses a bare
   name, so any code path that has not explicitly opted into resolution cannot be
   tricked into reaching a name. A consumer that needs named egress calls the
   resolving variant and connects to the returned, pinned IPs. This honours the
   "never weaken a default" rule: the strict check is unchanged; the new capability
   is additive and opt-in.

3. Fail closed in every uncertain case: an unresolvable host, a host that resolves to
   no addresses, an unparseable resolved address, or any resolved address in a
   blocked range raises `SSRFBlocked`. The vetted host is `urlparse(...).hostname`,
   so a public-looking userinfo prefix cannot mask the real (resolved) host.

4. Defer the wiring. The egress path that calls the resolver and pins the socket to
   the returned IP lands with the first server-initiated egress consumer (the HTTP
   transport, BL-012, or a cloud/redfish adapter). Until then the primitive is the
   tested, canonical helper such a consumer must use; BL-046 stays open for that
   wiring with an audit note.

## Consequences

Positive: the rebinding-aware resolve-and-check-and-pin logic exists, is fail-closed,
and is covered by tests (public-name allow with pinned return, rebinding to a private
address refused, every-resolved-IP checked, unresolvable/empty refused, IP literal
skips resolution, userinfo cannot mask the host); the strict default is unchanged, so
nothing is weakened; a future egress consumer inherits a vetted primitive instead of
re-implementing SSRF.

Negative: the primitive is not yet wired to a live egress path (none exists), so it is
exercised only by tests for now; the connection-pinning contract (the caller must
connect to the returned IP, not re-resolve) is a usage discipline the consumer must
honour and that this ADR can only document until that consumer exists.

Neutral: the returned value is a list of IP strings; the eventual consumer decides
how to use them (typically connect to the first, with the rest as fallbacks vetted
identically). The choice of `getaddrinfo` (A and AAAA) over a narrower lookup keeps
the check aligned with what the OS would actually connect to.

## Alternatives considered and rejected

- Change `assert_egress_allowed` to resolve names. Rejected: it weakens the
  deny-by-default for every existing and future caller that has not opted into
  resolution; an opt-in resolving variant keeps the strict default intact while
  adding the capability.
- Resolve and check, but let the caller re-resolve at connect time. Rejected: that
  is the DNS-rebinding hole the feature exists to close; returning the pinned IPs is
  the point.
- Wait for the egress consumer before adding any resolution. Rejected: BL-046 and the
  STPA SEC-7 coverage call for the rebinding-aware filter now; shipping the tested
  primitive de-risks the consumer and the security review is done once, here.

## Revisit triggers

- The first server-initiated egress consumer lands (HTTP transport BL-012, or a
  cloud/redfish adapter): wire it to `resolve_and_assert_egress_allowed`, pin the
  socket to a returned IP, and close the wiring half of BL-046.
- `getaddrinfo` behaviour or a new embedding form requires the resolved-address
  check to be extended (kept in lockstep with `_ip_is_blocked`).

## Audit note (2026-06-14)

The first server-initiated egress consumer has landed: the RFC 3161 timestamp stamper
(BL-095, ADR-0030). `src/praxis/audit/rfc3161.py::_https_post` calls
`resolve_and_assert_egress_allowed` and pins the HTTPS connection to each returned
vetted IP in turn, never re-resolving between the check and the connect, so it honours
the connection-pinning contract this ADR could previously only document. This satisfies
the first revisit trigger above and closes the wiring half of BL-046 (now resolved). The
decision is unchanged; this note records the factual update per the immutable-ADR
convention.
