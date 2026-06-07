# ADR-0006: MCP transport and auth posture

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

The MCP surface is the boundary between the model-driven plane and the fleet.
Exposing it carelessly (a routable bind, no auth, credential passthrough) hands an
attacker the actuator. MCP security guidance, NSA hardening notes, and the lethal
trifecta (ADR informed by SECURITY.md) all converge on a default-closed posture.

## Decision

1. stdio is the default transport. A laptop deployment exposes no network surface
   at all.
2. HTTP (streamable) is opt-in and requires, simultaneously:
   - a bearer token (`PRAXIS_HTTP_TOKEN`); without it HTTP refuses to start;
   - an explicit non-loopback opt-in (a literal env acknowledgement) before
     binding any address outside `127.0.0.1`/`::1`/`localhost`; the token alone
     does not authorize off-host exposure;
   - an SSRF egress filter on any server-initiated request that blocks
     link-local (169.254/16, fe80::/10), loopback, and RFC1918 ranges
     (10/8, 172.16/12, 192.168/16) plus CGNAT (100.64/10).
3. No token passthrough. A token presented to `praxis` is never forwarded to an
   upstream; upstream credentials are separate, scoped, and injected server-side.
4. A per-client consent registry records which client has consented to which tier
   ceiling; a client cannot exceed its recorded consent.
5. Tools carry accurate `readOnly` and `destructive` annotations so a client can
   reason about a call before making it. Annotations are descriptive, not the
   enforcement; enforcement is the executor (ADR-0005).

## Consequences

Positive: the default deployment is unreachable from the network; turning on HTTP
forces three deliberate, separately-failing decisions; SSRF cannot be used to
pivot into the private fleet network through the server.

Negative: enabling production HTTP is several steps, by design; misconfiguration
fails closed (refuses to start) rather than open.

Neutral: the consent registry is in-process for v0 (single operator); a
multi-operator deployment would externalize it.

## Alternatives considered and rejected

- HTTP on by default with a token. Rejected: a token alone does not stop a
  routable bind or an SSRF pivot; default-closed is the only safe default.
- Forward the client token to upstreams ("transparent auth"). Rejected: token
  passthrough is a confused-deputy and a credential-spray vector.

## Revisit triggers

- A multi-operator or multi-tenant deployment (externalize consent and tokens).
- A transport beyond stdio/HTTP is required.

## Audit note (2026-06-07, ADR-0012)

Decision 4 (the per-client consent registry) was specified here and presented as a
delivered control in `SECURITY.md`, but it was never built: the v0 code has zero
references to a consent registry (internal audit ADR-0012, finding BL-045).
Decisions 1 to 3 (stdio default, the HTTP token plus non-loopback opt-in plus SSRF
egress filter) and Decision 5 (tool annotations) are implemented and tested; the
consent ceiling is not. This note records the gap without rewriting the decision
(ADRs are immutable). Building the registry is a prerequisite for the multi-operator
deployment named in the revisit triggers. This audit note, plus the known-gaps
entry in `LIMITATIONS.md`, is the canonical record of the gap.
