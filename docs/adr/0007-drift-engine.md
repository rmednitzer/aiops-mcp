# ADR-0007: Drift engine, desired-state sources, and reconciliation

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

Drift in the prototype was manual markdown: an operator eyeballed a host against a
remembered baseline. That does not scale, is not queryable, and silently produces
false negatives (loss L-5). At the same time, an over-eager reconciler that
"fixes" drift automatically can destroy a valid configuration (loss L-2). The
engine must detect rigorously and converge only under a human gate.

## Decision

1. The engine is observe -> diff -> converge, and the three are separate. Observe
   and diff are T0 (read-only); converge is actuation (T2+ through ADR-0005), never
   automatic.
2. Desired state comes from three authorities, each wrapped, never reinvented:
   - IaC plan: `tofu plan -refresh-only -json` (what infrastructure should be).
   - config baseline: `ansible-playbook --check --diff` (what configuration should
     be).
   - an operator-blessed known-good snapshot stored as facts (what we last
     declared correct).
   The desired-state authorities remain those tools; `praxis` does not become an
   IaC or CM engine (LIMITATIONS).
3. A diff produces structured `drift findings` written into the store as
   bitemporal facts (ADR-0003), so drift has history: when it appeared, when it
   was resolved, and what the observed-vs-desired delta was.
4. Convergence is framed as an actuation request that must pass DRY_RUN -> human
   approval -> execute (ADR-0004 tier gate). The engine proposes; the operator
   disposes. A finding never auto-triggers a fix.
5. Collected host data feeding the observe step is untrusted (invariant 8); the
   diff step treats it as data, never as instructions.

## Consequences

Positive: drift becomes a queryable, historical fact stream; detection is
decoupled from (human-gated) remediation, so L-2 and L-5 are addressed
separately; the existing IaC/CM tools stay authoritative.

Negative: convergence is never one-click; an operator is always in the loop for a
fix (intended).

Neutral: the known-good snapshot is operator-curated; its freshness is itself a
drift signal.

## Alternatives considered and rejected

- GitOps-style continuous auto-reconciliation. Rejected: auto-apply against a
  heterogeneous, partly-immutable fleet risks L-2; the human gate is the point.
- A bespoke desired-state DSL. Rejected: the fleet already has OpenTofu and
  Ansible as the source of desired state; wrap them.

## Revisit triggers

- A fourth desired-state authority is added.
- A class of drift is safe to auto-remediate (would need its own ADR and STPA
  re-analysis).
