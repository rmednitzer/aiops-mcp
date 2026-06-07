# ADR-0003: Bitemporal fact model

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

The fleet model must answer two distinct questions: "what is true now" and "what
did we believe at time T". A drift engine that overwrites state in place cannot
explain why a past decision was made, cannot distinguish a real-world change from
a correction of a mistaken observation, and destroys the evidence an audit needs.
Loss L-3 (audit tampering) and L-5 (undetected model divergence) both bear on the
state layer, not only the audit log.

## Decision

1. Every fact carries four timestamps:
   - `t_valid`: when the fact became true in the world.
   - `t_invalid`: when it stopped being true in the world (null while active).
   - `t_recorded`: when the system recorded it (transaction time start).
   - `t_superseded`: when the system replaced this record (transaction time end;
     null while it is the current record).
   The (valid, recorded) pair is the standard bitemporal model.
2. Facts are append-only. Deletion is blocked at the storage layer (ADR-0002). A
   correction does not mutate or remove the prior row; it supersedes it, carrying
   an `actor` and a `reason`.
3. A fact is keyed by `(subject, predicate, fact_type)`. At most one row per key
   is active (the active-fact unique constraint). Recording a new value for an
   existing key supersedes the prior active row in the same transaction.
4. "Active" means `t_invalid IS NULL AND t_superseded IS NULL`: true in the world
   and not yet replaced in the record.
5. History is reconstructable: `history(subject, predicate)` returns every row in
   recorded order, so any past belief state is recoverable.

## Consequences

Positive: the model can be queried as-of any past instant; corrections are
distinguishable from real-world changes (recorded time moves, valid time does
not); the audit narrative is complete; no decision rests on a silently mutated
fact.

Negative: storage grows monotonically (mitigated by retention policy on
superseded rows, out of scope for v0); every write is a read-then-supersede, not
a blind upsert.

Neutral: the four-timestamp shape is uniform across vertex facts and edges.

## Alternatives considered and rejected

- Uni-temporal (valid time only). Rejected: cannot distinguish a correction from
  a real change, which is exactly the distinction drift reconciliation needs.
- Soft-delete flag. Rejected: a single boolean cannot answer as-of queries and
  invites in-place mutation.
- Event-sourcing with projections only. Rejected for v0: more machinery than a
  single-operator deployment needs; the supersession model gives the same
  auditability with a simpler query surface.

## Revisit triggers

- Retention pressure requires pruning superseded rows.
- A fact needs decision time as a fifth axis (rare; record in a new ADR).
