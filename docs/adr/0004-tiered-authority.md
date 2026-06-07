# ADR-0004: Tiered authority T0-T3 made load-bearing

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

In the prototype, "graduated autonomy" was a design note: a human read a tier
label and decided. Nothing in code enforced it, so an irreversible action could
run with the same ceremony as a read. STPA hazard H-3 (tier under-rating) and
loss L-1 (unauthorized privileged command) trace directly to this gap.

## Decision

1. Four tiers, ordered, each with a fixed gate:
   - T0 observe: read-only, no approval.
   - T1 reversible: act, log, notify; no human confirm.
   - T2 stateful: human confirm with a rollback plan recorded.
   - T3 irreversible: two-step confirm with a typed confirmation token plus
     before/after evidence; one target at a time.
2. `classify(tool, command)` is conservative and rounds up: on ambiguity it
   returns the higher tier. Any command containing `sudo`, `doas`, or `pkexec` is
   at least T2. The classifier lives in `execution/patterns.py`, the sole
   security-review file, behind a `PATTERNS_VERSION` counter.
3. Three modes gate which tiers may run: `open` (all tiers, subject to their
   gates), `guarded` (T0-T2; T3 refused), `readonly` (T0 only). The mode is set
   at server start; tools cannot raise their own ceiling.
4. The deny list is global and unconditional. It is checked first, before tier
   gating, and applies in every mode including `open`. A denied pattern is never
   executed regardless of approval.
5. Tier classification, mode gating, and the deny list are enforced inside the
   single execution path (ADR-0005), so no tool can opt out.

## Consequences

Positive: autonomy is enforced, not advised; ambiguity fails safe (up, not down);
a misclassified-low action cannot slip a gate; an operator can drop the whole
server to `readonly` or `guarded` without editing tools.

Negative: conservative rounding produces occasional false-high classifications
that ask for confirmation when strictly unnecessary; that is the intended
trade-off.

Neutral: the tier of a given command can change as `patterns.py` evolves;
`PATTERNS_VERSION` makes that change reviewable and auditable.

## Alternatives considered and rejected

- Per-tool static tier labels only. Rejected: the same tool (a shell) spans tiers
  depending on the command; classification must read the command, not just the
  tool name.
- Allow-list instead of deny-list-first. Rejected: an allow-list is the right
  shape for capabilities but cannot express "never, in any mode"; the global deny
  list is the unconditional floor beneath the mode gates.

## Revisit triggers

- A fifth tier or a sub-tier is needed.
- Mode semantics must vary per client (multi-operator; out of v0 scope).
