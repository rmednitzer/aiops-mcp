# ADR-0008: Tamper-evident audit and evidence

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

An audit trail that can be silently edited is worse than none: it manufactures
false confidence (loss L-3). The trail is also the evidence base for the
compliance mapping (EU AI Act Art. 12, ISO 27001). It must be append-only,
verifiable after the fact, and resistant to a compromised host clock or a tampered
file.

## Decision

1. Each audit record stores `output_sha256` and `output_len`, never the output
   body. Bodies can carry secrets and unbounded attacker-influenced content; the
   hash proves what ran without retaining it (invariant 3).
2. The log is append-only JSONL with a per-entry hash chain: each record commits
   to the previous record's hash, so any insertion, deletion, or edit breaks the
   chain at a detectable point.
3. The audit writer is a separate concern from the audited process (a supervisor
   writer), so a crash in tool execution cannot truncate a half-written record,
   and the writer's failure modes are isolated.
4. Construction of the logger never raises. If the configured sink is unavailable
   it degrades to stderr; an audit subsystem that fails to start must not take the
   server down or, worse, allow execution to proceed unaudited.
5. Periodically the chain is committed to a Merkle root (RFC 6962 domain
   separation: leaf prefix 0x00, node prefix 0x01), the root is stamped with an
   RFC 3161 timestamp (verification is fail-closed), and optionally anchored in a
   transparency log (Rekor). The server-binary hash is bound into the session
   header so the evidence ties output to the exact build that produced it.
6. Parameters are logged redacted (ADR cross-ref to redaction); secret values are
   never written.

## Consequences

Positive: tampering is detectable, not merely discouraged; evidence survives a
hostile host; no secret or unbounded body is retained; verification is offline and
reproducible.

Negative: the hash chain must be written in order and verified end to end;
out-of-order or parallel writers need the supervisor to serialize them.

Neutral: Rekor anchoring is optional and network-dependent; the Merkle + RFC 3161
layer works offline.

## Alternatives considered and rejected

- Store output bodies for completeness. Rejected: bodies carry secrets and
  attacker content; the hash is sufficient proof and far safer.
- A plain append-only file without a chain. Rejected: append-only by convention is
  not tamper-evident; an editor can still rewrite history undetectably.
- Sign every record individually. Rejected for v0: a hash chain plus periodic
  Merkle + RFC 3161 gives tamper evidence at far lower key-management cost; the
  binary hash binds provenance.

## Revisit triggers

- A regulator requires per-record qualified signatures.
- Multi-writer concurrency outgrows the single supervisor.
