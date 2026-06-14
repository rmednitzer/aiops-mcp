# ADR-0023: Audit and evidence retention tiers (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (implements ADR-0011 finding 035 / BL-035)

## Context

ADR-0011 finding 035 recorded that the audit and evidence chain had no documented
retention policy, and accepted the remedy as "documented tiers bound in config":
NIS2 Art. 23 (incident reporting and evidence) and ISO/IEC 27001 A.8.15 (logging)
both expect a defined, auditable log-retention period. The control was specified
there but never implemented; BL-035 tracked it.

The constraint that shapes the implementation is that the trail is append-only by
construction: the audit log is a per-record hash chain written to an owner-only
`O_APPEND` sink, and the evidence (Merkle checkpoints) and anchor (high-water mark)
files are likewise never rewritten in place (invariant 4, SEC-9, SEC-10, ADR-0008,
ADR-0019). A retention policy therefore cannot be a runtime delete or an in-place
truncate without defeating the integrity guarantees it exists to support. Retention
here means how long a closed file is kept before archival, enforced at the storage
layer, with the declared period bound in config as the single source of truth.

## Decision

1. Add two retention tiers to `Config`, bound from the environment as the single
   source of truth: `PRAXIS_AUDIT_RETENTION_DAYS` and
   `PRAXIS_EVIDENCE_RETENTION_DAYS`, each defaulting to 365 days. A value of `0`
   means retain indefinitely; a negative or non-numeric value degrades to the
   default (fail safe toward retaining, never to a shorter tier). The anchor file
   follows the evidence tier (it is a derived high-water mark, not a separate
   record class).

2. Bind the declared policy into the trail. `bind_session` gains an additive
   `retention` argument; the server passes `Config.retention_args`, so the
   retention in force is written into the first session audit record and becomes
   part of the tamper-evident provenance, not documentation alone. Omitting the
   argument preserves the prior record shape (additive-stability rule).

3. Enforce retention at the storage layer, not in the server: document (SECURITY.md,
   `docs/runbooks/operate.md`, the compliance map) that a tier is applied by
   time-based archival of whole closed files (archive-then-rotate, or a WORM store
   with a retention class), keeping the audit file together with its evidence and
   anchor sidecars so a retained window stays independently verifiable. An in-place
   truncate or a `logrotate` `copytruncate` is explicitly prohibited because it
   breaks the hash chain, the Merkle coverage, and the `O_APPEND` owner-only sink.

This adds no deletion path and no new runtime behavior beyond recording the policy;
it makes the retention posture declarable, auditable, and operationally specified.

## Consequences

Positive: the last ADR-0011 governance finding for the audit chain is closed; the
retention period is one declared value mapped to NIS2 Art. 23 and ISO 27001 A.8.15,
and is itself captured in the tamper-evident trail; the append-only integrity
guarantees are preserved because enforcement is archival, not deletion.

Negative: enforcement depends on an external archival job or a WORM store that the
repo cannot ship or test end to end; a misconfigured rotation (`copytruncate`) would
still damage the chain, so the prohibition is documented and load-bearing rather
than mechanically enforced. The config values are advisory to that job; the server
does not act on expiry.

Neutral: the tiers are coarse (per artifact class, not per record sensitivity),
which suits a single-operator append-only trail; a finer scheme can supersede this
if a backend gains native record-level retention.

## Alternatives considered and rejected

- Enforce retention by deleting or truncating expired records in the server.
  Rejected: it defeats invariant 4, SEC-9, and SEC-10 (append-only, no in-place
  mutation, hash-chained), the very properties retention evidence depends on.
- A single global retention value. Rejected: the audit log and the evidence and
  anchor files have different volumes and verification roles; two tiers (with the
  anchor following evidence) lets an operator keep dense evidence checkpoints on a
  different schedule from the full log without losing verifiability.
- Document retention in prose only, not bound in config. Rejected: ADR-0011
  accepted "bound in config" specifically so the period is a single auditable
  value, not a number that drifts between a runbook and an operator's job.

## Revisit triggers

- A store or audit backend gains native time-based WORM or record-level retention,
  at which point enforcement can move from an external job into the storage layer.
- A regulator or customer sets a specific minimum retention that should become the
  default or a validated floor.
- The HTTP transport (BL-012) or a multi-client deployment changes the retention or
  archival requirements (for example per-tenant tiers).
