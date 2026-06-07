# STPA and STPA-Sec analysis

System-Theoretic Process Analysis (Leveson and Thomas, MIT) is the method by which
this project derives its safety and security requirements. STPA-Sec extends it by
treating an adversary as a cause that actively drives unsafe control actions.

This directory is the authoritative hazard analysis. The traceability chain is:
**security constraint -> the UCA it prevents -> the loss scenario it mitigates ->
the loss it avoids**. Every state-changing MCP tool must appear in the UCA table;
every constraint must map to an enforcement mechanism (a code assertion, a policy
rule, or a human-in-the-loop gate).

## Artifacts (to be completed in build-sequence step 0)

- `01-losses.md` numbered losses (L-1..).
- `02-hazards.md` hazards (H-1..) mapped to losses.
- `03-system-constraints.md` system-level constraints (SC-1..).
- `04-control-structure.md` the control-structure diagram and narrative
  (operator -> MCP server -> tool dispatcher -> fleet hosts, with feedback paths
  and trust boundaries).
- `05-ucas.md` the Unsafe Control Action table (controller x control action x the
  four modes: not provided, provided when it should not be, wrong timing/order,
  wrong duration x hazard).
- `06-loss-scenarios.md` causal-factor tables per UCA, including adversary-driven
  paths (for example, indirect prompt injection in collected host data).
- `07-security-constraints.md` the derived mitigations, each mapped to its
  enforcement mechanism.

## Seed losses (draft)

- L-1 Unauthorized or unintended privileged command executes on a fleet host.
- L-2 A valid host configuration is destroyed by an erroneous reconciliation.
- L-3 The audit trail is silently tampered with or incomplete.
- L-4 Sensitive data (credentials, keys, classified host facts) is disclosed.
- L-5 The fleet model diverges from reality without detection (false-negative
  drift), so decisions are made on a stale picture.

## Seed hazards (draft)

- H-1 A state-changing tool is invoked without validating operator intent (no HITL
  gate at T2+).
- H-2 An audit record is written after execution, or not at all.
- H-3 Tier classification under-rates an action (an irreversible action treated as
  reversible).
- H-4 Collected, attacker-influenced content is allowed to authorize actuation in
  the same session (the lethal trifecta).
- H-5 Actuation targets the wrong host type (for example, an SSH path attempted
  against an immutable Talos node).

## Seed system-level constraints (draft)

- SC-1 Every state-changing tool call MUST produce an immutable audit record
  before execution.
- SC-2 Every action at T2 or above MUST require a human confirmation; T3 MUST
  require a typed token and operate on one target at a time.
- SC-3 Tier classification MUST be conservative (round up on ambiguity).
- SC-4 A single session MUST NOT hold sensitive data, untrusted content, and
  actuation capability simultaneously without a human gate between phases.
- SC-5 Actuation MUST branch on host_type and MUST NOT use SSH against a Talos
  host.
