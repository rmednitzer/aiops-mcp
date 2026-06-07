# ADR-0009: STPA/STPA-Sec as the requirements-derivation method

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

A security-first control plane needs its requirements to come from somewhere
defensible, not from a checklist of remembered attacks. The system is a control
loop (operator commands flow down through the MCP server to hosts; feedback flows
back up), which is exactly what System-Theoretic Process Analysis (Leveson and
Thomas, MIT) is built to analyse. STPA-Sec extends it by treating an adversary as
a cause that actively drives unsafe control actions, which fits a model-driven
plane exposed to prompt injection.

## Decision

1. STPA is the method by which safety and security requirements are derived. The
   analysis lives in `docs/stpa/` and is authoritative over ad-hoc control ideas.
2. The traceability chain is fixed and load-bearing:
   security constraint -> the Unsafe Control Action (UCA) it prevents -> the loss
   scenario it mitigates -> the loss it avoids.
3. Coverage rules, enforced by review and (where feasible) by test:
   - every state-changing MCP tool appears in the UCA table (`05-ucas.md`);
   - every security constraint (`07-security-constraints.md`) maps to an
     enforcement mechanism: a code assertion, a policy rule, or a HITL gate.
4. The UCA table considers the four STPA modes for each control action: provided
   when it should not be, not provided when it should be, wrong timing/order, and
   wrong duration (applied/stopped too soon or too late).
5. Loss scenarios include adversary-driven paths explicitly (for example, indirect
   prompt injection in collected host data driving an unsafe actuation), per
   STPA-Sec.

## Consequences

Positive: requirements are derived, not guessed; coverage is checkable (a tool
without a UCA row, or a constraint without an enforcement, is a visible gap); the
compliance map (governance) rests on the same constraint set.

Negative: adding a state-changing tool now carries an STPA obligation (a UCA row
and a mapped constraint), which is friction by design.

Neutral: STPA artifacts are documents; the enforcement they map to is the code and
tests in the rest of the repo.

## Alternatives considered and rejected

- A control checklist (CIS-style) as the primary source. Rejected: a checklist is
  a cross-check, not a derivation; it does not explain why a control exists or what
  loss it prevents.
- Threat modelling (STRIDE) only. Rejected: STRIDE enumerates threats per element
  but does not naturally model the control-loop and feedback structure that is the
  heart of this system; STPA-Sec subsumes the adversary view within that structure.

## Revisit triggers

- The control structure changes materially (a new controller or a new actuated
  process).
- A loss is discovered that the current hazard set does not cover.
