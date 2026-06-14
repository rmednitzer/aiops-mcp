# ADR-0038: Audit request/client correlation identifiers (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes BL-101)

## Context

The audit record (ADR-0008; SEC-9, invariant 3) stores `output_sha256` + `output_len`
(never the body), the redacted args, the tier, the decision, and the hash-chain fields.
It carried no per-request correlation: concurrent calls could be tied to their audit
entries only by timestamp matching, which is fragile under concurrency. The HTTP
transport (BL-012) will serve multiple clients, so the need is real once concurrency
arrives.

BL-101 asked to thread the MCP request id and a client id into the audit record,
optional and additive. The audit record shape is an L1 surface, and the
additive-stability rule (CLAUDE.md) permits extending it additively (new optional
fields), so this adds fields rather than changing a signature.

## Decision

1. Add two optional fields to `AuditRecord` and `AuditLogger.record`: `request_id` and
   `client_id` (default `None`). They are part of the hashed payload, so each record
   self-describes: `verify_chain` stays consistent, and old records (without the fields)
   and new records (with them) each verify against their own stored payload.

2. Thread them ambiently with `contextvars` (`execution/correlation.py`):
   `request_scope(request_id=..., client_id=...)` is entered by the transport per
   request, and `current_request_id()` / `current_client_id()` are read by `run`'s audit
   helper. The identifiers are request-scoped, not tool inputs, so no tool signature
   changes.

3. The stdio transport binds the JSON-RPC request id as `request_id` around the
   `tools/call` dispatch. `client_id` stays `None` for the single-client stdio
   transport; a multi-client transport (HTTP, BL-012) sets it via `request_scope`.

4. Bound the client-supplied id: `bound_id` coerces (`str` / `int` / other via `str`),
   strips, drops empty/whitespace, truncates to `MAX_ID_LEN` (128), and never raises,
   even on a hostile `__str__`. A hostile or careless client cannot bloat the audit
   record or break the audited path (SEC-9 hygiene, invariant 3).

## Consequences

Positive: BL-101 is closed. Concurrent calls correlate to their audit entries by id
rather than timestamp, and the plumbing is ready for HTTP multi-client: `client_id`
flows the moment a multi-client transport sets it, with no change to the audit or runner
layers. `correlation.py` is 100% covered and the audit module stays at 96%; the change
is additive with no L1 break.

Negative: for the stdio single-operator default, `request_id` is the only populated
field and `client_id` is always `None`, so the immediate value is low (as BL-101 noted);
the value lands with the HTTP transport.

Neutral: the identifiers are inside the hashed payload, so they are tamper-evident like
every other field. They are not redacted (they are opaque correlation ids, not secrets)
but they are bounded. `contextvars` make them per-thread / per-task, which is correct for
both the synchronous stdio loop and a future concurrent transport.

## Alternatives considered and rejected

- Add `request_id` / `client_id` to `ExecutionRequest` and thread them through every
  tool. Rejected: the ids are request-scoped, not tool inputs; threading them through
  every tool signature is invasive and would touch the L1 tool surface. `contextvars`
  keep the change additive and localised to the transport and the audited path.
- Read the contextvars inside `record()` itself so every record auto-correlates.
  Rejected: `record()` stays pure (explicit params) and testable; `run` does the one
  ambient read, and the session-header record (not request-scoped) correctly gets
  `None`.
- Leave correlation to timestamp matching. Rejected: fragile under concurrency, which is
  exactly the BL-012 HTTP case BL-101 anticipates.
- Synthesise a constant `client_id` for stdio (e.g. `"stdio"`). Rejected: a constant
  adds no correlation value and would misrepresent a single client as identified; `None`
  is honest until a multi-client transport supplies a real id.

## Revisit triggers

- The HTTP transport (BL-012) serves multiple clients: set `client_id` in its
  `request_scope` from the authenticated connection; no change to the audit/runner
  layers.
- A correlation id needs to span tool-internal sub-operations: extend `request_scope`
  nesting or add a span id beside `request_id`.
