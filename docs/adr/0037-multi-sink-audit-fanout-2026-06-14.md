# ADR-0037: Multi-sink audit fan-out with per-sink containment (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes BL-100: the second-sink prerequisite and the `MultiSink`)

## Context

The audit logger (ADR-0008; SEC-8, SEC-9, invariant 3) writes to a single
append-only, hash-chained file sink, degrading to stderr if the file cannot be
opened or written. It stores `output_sha256` + `output_len` (never the body),
redacts params, and never raises, so a failed audit subsystem can never silently
permit an unaudited run.

BL-100 asked for a `MultiSink` with per-sink failure containment, but it was
deliberately latent: with only one sink there is nothing to contain. Operators
running praxis next to a SIEM or journald want the audit trail forwarded to a
second destination for visibility and independent retention, without compromising
the tamper-evident file or the never-raise / never-silently-skip guarantees.

The repo already has the containment pattern this calls for: the routing-chain
dispatcher (`skills/dispatch.py`, the "BL fan-out class") contains a per-link
`Exception` so one bad matcher cannot abort the route. BL-100 is that pattern
applied to the audit write side.

## Decision

1. Add a second sink (the prerequisite): `SyslogAuditSink`. It forwards each
   canonical, already-redacted audit line to a syslog endpoint over a datagram
   socket: a Unix socket path (default `/dev/log`) when the address starts with
   `/`, otherwise `host:port` for a remote UDP collector. The connection is lazy
   and re-established after a failure, so construction never raises and a daemon
   that starts later is picked up. It is opt-in via `PRAXIS_AUDIT_SYSLOG_ADDRESS`
   (unset by default).

2. Add the `MultiSink` (the deliverable): it fans one line out to N secondary
   sinks and contains a per-sink `Exception`, noting a failing sink once per
   failure streak rather than on every record. `BaseException` (such as
   `KeyboardInterrupt`) still propagates. `emit` itself never raises.

3. The primary append-only, hash-chained file stays authoritative and is written
   first, directly, on the unchanged path. Secondary sinks are fanned out only
   after the primary write, through the contained `MultiSink`. A failing, slow, or
   oversized secondary can therefore never affect the primary write, the hash
   chain, the `seq`, or the other secondaries; `verify_chain` reads the file
   alone. "One failing sink cannot silence the others" holds across the primary
   and all secondaries by construction.

4. Never weaken a default. The default is the single file sink, posture unchanged.
   Secondaries are opt-in and best-effort, and they carry the same redacted line
   as the file (no output body, no secret; SEC-9), so forwarding discloses nothing
   the file does not already hold. Tamper-evidence lives only in the file; syslog
   is for visibility, not a source of truth (it may truncate or drop an oversized
   datagram, which is contained).

## Consequences

Positive: BL-100 is closed. An operator can forward the audit trail to
journald/SIEM with a single environment variable, and the `MultiSink` generalises
to further sinks (a mirror file on another volume, a future Postgres audit path)
with the same containment for free. The authoritative file and the invariant 3
guarantees are untouched; the audit module stays at 96% line coverage.

Negative: syslog is best-effort and not tamper-evident; an oversized record may be
truncated or dropped by syslog (contained, the file stays complete). The secondary
fan-out runs under the audit lock, so a secondary must be non-blocking (a
datagram); a blocking sink would serialise writers. This is documented and
enforced by choosing `SOCK_DGRAM`.

Neutral: the primary is deliberately outside the `MultiSink`, written first and
directly, so it can never be silenced by a best-effort fan-out. Records reaching
syslog are the same redacted lines the file holds.

## Alternatives considered and rejected

- Put the primary file inside the `MultiSink` as just another sink. Rejected: the
  tamper-evident file must be written first and directly, never at the mercy of a
  best-effort fan-out's ordering or containment. Keeping it separate is the
  stronger security design and still satisfies "one failing sink cannot silence
  the others".
- A second file (a mirror) as the second sink. Rejected as the first choice: low
  marginal value on the same medium. The `MultiSink` admits it additively if an
  operator wants a second-volume mirror.
- The Postgres audit path as the second sink. Deferred: it needs the `postgres`
  extra (not dependency-free for the core) and a cross-process write story. Syslog
  is dependency-free and the canonical forward target; the `MultiSink` admits a PG
  sink later without change.
- Reuse the existing `on_record` hook for syslog. Rejected: `on_record` is gated
  on not-degraded (so syslog would stop forwarding exactly when the file fails,
  the opposite of what a forward wants) and is single-consumer (the evidence
  scheduler). A dedicated sink layer is clearer and keeps forwarding alive even if
  the file degrades.
- Self-contain syslog failures inside the sink (swallow them). Rejected: the sink
  raises and the `MultiSink` contains, so containment lives in one place (BL-100's
  `MultiSink`) and a future sink author inherits it.

## Revisit triggers

- A Postgres or other cross-process audit sink is wanted: add it as an
  `AuditSink`; the `MultiSink` already contains it.
- A blocking (stream/TLS) syslog transport is needed: move the secondary fan-out
  off the audit lock (a bounded queue and a worker) so a slow sink cannot
  serialise writers.
- BL-101 (request_id/client_id correlation) lands: the richer record flows to all
  sinks unchanged.
