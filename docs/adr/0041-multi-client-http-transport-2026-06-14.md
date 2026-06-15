# ADR-0041: Multi-client HTTP transport (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (BL-012 serving loop; closes BL-045, BL-104, BL-106, BL-107)

## Context

ADR-0006 set the MCP transport posture: stdio by default, and an opt-in HTTP transport
that requires, simultaneously, a bearer token, an explicit non-loopback opt-in, and an
SSRF egress filter, plus a per-client consent registry (Decision 4) and accurate tool
annotations. The guard (`validate_transport`) and the annotations were built and tested,
but the HTTP serving loop itself was staged: `server.serve` raised `NotImplementedError`
for HTTP, recorded in `LIMITATIONS.md`. Decision 4's consent registry was never built
(the ADR-0006 audit note / BL-045).

The 2026-06-14 deep audits flagged the prerequisites for serving multiple clients safely:
per-session isolation of the trifecta taint latch and the approval registry, an atomic
check-and-burn for the single-use nonce (BL-104), a constant-time token comparison
(BL-106), and a total request-body cap (BL-107). This ADR builds the serving loop and
those prerequisites together.

## Decision

1. Stdlib `http.server` only: no third-party web framework (dependency posture,
   ADR-0001/0014). A single-threaded `HTTPServer` serves one request at a time, so the
   single-connection SQLite store is never touched from two threads; correctness of the
   bitemporal/append-only invariants under concurrency is not at stake. Concurrent
   serving over a thread-safe store is deferred (BL-110). The HTTP machinery is imported
   lazily inside `serve`, so the stdio default path is unchanged.

2. Transport-agnostic dispatch: `mcp_handle` / `mcp_call` are extracted from
   `StdioServer`; both transports share them. The HTTP handler calls `mcp_handle` with
   the per-session `ServerContext` and the session id as `client_id` (ADR-0038).

3. Sessions: `initialize` mints an `Mcp-Session-Id` and a per-session `ServerContext`;
   every other method requires a known session id (404 otherwise, so a forged or expired
   id cannot act). A per-session context SHARES the global parts (the one audit hash
   chain, the store, the global kill switch, the credential broker, the evidence
   scheduler, the immutable policy, and the approval sink) and has FRESH per-session state
   (the trifecta taint latch, the approval registry, the budget, and the consent ceiling).
   One client's taint or pending nonce can therefore never affect another (invariant 8,
   BL-104).

4. Auth: every request carries `Authorization: Bearer <token>`, compared in constant time
   on bytes (BL-106). The token is never forwarded anywhere (no passthrough, ADR-0006).
   A failure returns 401 and closes the connection, so an unread body cannot desync a
   keep-alive socket or be streamed at an unauthenticated server.

5. Body cap: `Content-Length` is checked before the body is read; absent, non-integer,
   negative, or over the 16 MiB cap is refused (411/413) and the connection closed,
   bounding an untrusted client (BL-107).

6. Consent ceiling (ADR-0006 Decision 4, BL-045): a session may declare `consentCeiling`
   (`T0`..`T3`) in the `initialize` params; an action classified above the recorded
   ceiling is denied in the audited path (`run` step 3a), audited like any other denial.
   Absent leaves the session gated only by the server mode (the stdio-equivalent
   default); a malformed value fails closed to `T0` (reads only). With a single shared
   token every session is the same operator, so distinct per-client ceilings await
   per-client tokens (the ADR-0006 multi-operator revisit trigger); the registry and the
   in-path enforcement are now delivered.

7. Approval hardening (BL-104, BL-106): `ApprovalRegistry` mint/validate/consume are
   lock-guarded and the check-and-burn is atomic under one lock acquisition, so two
   concurrent requests presenting the same nonce cannot both pass validation before
   either burns it; token matching is constant-time and byte-based, so a hostile
   non-ASCII token is refused rather than raising out of the audited path.

## Consequences

Positive: BL-012's serving loop is delivered, and with it BL-045 (consent), BL-104
(isolation + atomic consume), BL-106 (constant-time token), and BL-107 (body cap). Many
isolated client sessions are served with no new dependency. Every action across every
session lands in one tamper-evident audit chain, distinguished by `request_id` /
`client_id`. The approval nonce still surfaces out-of-band on the server console (never in
the HTTP response), so the human-binding gate (BL-072) holds over HTTP: a client gets
"approval required" and the operator reads the nonce from the console.

Negative: single-threaded serving serialises requests, so a slow actuation blocks other
clients; true concurrency needs a thread-safe store (BL-110). There is no SSE streaming in
v1 (request/response only). The consent ceiling under a single shared token is a session
self-restriction, not a per-distinct-client control until per-client tokens exist.

Neutral: the consent ceiling defaults to the server mode (no extra restriction), so a
standard MCP client behaves as on stdio; a client opts to a lower ceiling. The session id
is a server-issued high-entropy capability gated behind the bearer token on every request.

## Alternatives considered and rejected

- A web framework (FastAPI/Starlette/uvicorn) or an ASGI server. Rejected: it would add a
  runtime dependency against the self-contained posture (ADR-0001/0014); stdlib
  `http.server` is sufficient for a single-operator request/response surface.
- `ThreadingHTTPServer` for concurrent serving in v1. Rejected: the default SQLite store
  is a single connection with `check_same_thread=True`; making the store thread-safe
  without risking the append-only/bitemporal invariants is a larger change, deferred to
  BL-110. Single-threaded serving delivers the isolation (the security goal) without that
  risk.
- Full MCP Streamable HTTP with an SSE channel. Rejected for v1: a tools-only server has
  no server-initiated streaming need; POST request/response plus `Mcp-Session-Id`
  suffices. SSE is an additive follow-up.
- Defaulting the consent ceiling to `T0` (deny actuation until an explicit consent).
  Rejected as the default: it would silently break a standard MCP client that does not
  send the parameter. The operator-set server mode remains the ceiling; consent is an
  opt-in self-restriction. A future per-client-token model would default new clients to
  `T0`.
- A global approval registry keyed by session id. Rejected: a per-session registry
  isolates nonces by construction and is simpler.

## Revisit triggers

- Concurrent serving is wanted: make the store thread-safe and switch to
  `ThreadingHTTPServer` (BL-110).
- Per-distinct-client consent ceilings are wanted: issue per-client tokens and key the
  consent registry by client identity (the ADR-0006 multi-operator revisit).
- An MCP client requires SSE streaming: add the Streamable-HTTP SSE channel.
