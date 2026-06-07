# ADR-0005: Execution trust boundary (vendored-and-fused core)

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

Tiering (ADR-0004), redaction, audit (ADR-0008), and contract enforcement are
only as strong as the guarantee that no tool can run without passing through them.
If these concerns live in separate libraries a caller can compose incorrectly, or
in a tool that forgets one step, the invariant is advisory. Invariant 1 (single
audited execution path) is the spine of the whole security model.

## Decision

1. Vendor and fuse the execution concerns into one in-repo package,
   `src/praxis/execution/`, evolved as a single unit with one security-review
   surface (`patterns.py`). No external execution library is a dependency.
2. There is exactly one entry point, `runner.run(...)`. Its ordered pipeline is
   fixed and total:
   classify tier -> policy check (deny-first, unconditional) -> redact audited
   args -> contract preconditions/invariants -> execute -> bounded error
   formatting (never raw tracebacks) -> truncate output -> write the audit record.
   Every read tool and every act tool calls `run`; nothing executes a host
   operation outside it.
3. The audit record is written for every call, including failures and denials. A
   denial or a precondition failure is itself an audited outcome.
4. Credentials are scoped per role, injected at the boundary, never logged, and
   independently revocable. A kill switch disables execution globally and
   immediately (the runner refuses with an audited denial when tripped).
5. Retry is bounded: at most one retry, and a retry of a gated (T2+) action
   requires a fresh approval; an approval is never reused.

## Consequences

Positive: one place to review, test, and harden; the invariants cannot be bypassed
by a forgetful tool; the kill switch is real because there is a single chokepoint
to trip.

Negative: the runner is a single point of failure and a hot path; it must stay
small, total, and exhaustively tested.

Neutral: actuation adapters (ADR-0007 neighbours) wrap real tools but always call
through `run`; they hold no execution authority of their own.

## Alternatives considered and rejected

- Compose existing libraries (a policy lib, an audit lib) at each call site.
  Rejected: composition is the bug; a forgotten step is an unaudited execution.
- A decorator applied per tool. Rejected: a decorator is opt-in and forgettable; a
  single mandatory entry point is not.

## Revisit triggers

- A class of operation genuinely cannot fit the linear pipeline.
- Capability isolation (container/seccomp) is brought in-tree (currently an
  out-of-tree extension point per LIMITATIONS).
