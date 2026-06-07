# STPA and STPA-Sec analysis

System-Theoretic Process Analysis (Leveson and Thomas, MIT) is the method by which
this project derives its safety and security requirements. STPA-Sec extends it by
treating an adversary as a cause that actively drives unsafe control actions.

This directory is the authoritative hazard analysis. The traceability chain is:
**security constraint -> the UCA it prevents -> the loss scenario it mitigates ->
the loss it avoids**. Every state-changing MCP tool must appear in the UCA table;
every constraint must map to an enforcement mechanism (a code assertion, a policy
rule, or a human-in-the-loop gate).

## Artifacts (complete; BL-003)

- [`01-losses.md`](01-losses.md) numbered losses (L-1..L-6).
- [`02-hazards.md`](02-hazards.md) hazards (H-1..H-10) mapped to losses.
- [`03-system-constraints.md`](03-system-constraints.md) system-level constraints
  (SC-1..SC-10).
- [`04-control-structure.md`](04-control-structure.md) the control-structure
  diagram and narrative (operator -> MCP server -> execution path -> fleet hosts,
  with feedback paths and trust boundaries).
- [`05-ucas.md`](05-ucas.md) the Unsafe Control Action table (every state-changing
  tool x the four modes: provided wrongly, not provided, wrong timing/order, wrong
  duration x hazard).
- [`06-loss-scenarios.md`](06-loss-scenarios.md) causal-factor scenarios per UCA,
  including adversary-driven paths (indirect prompt injection in collected host
  data).
- [`07-security-constraints.md`](07-security-constraints.md) the derived
  mitigations (SEC-1..SEC-10), each mapped to its enforcement mechanism and a
  proving test. This is the keystone traceability table.

The seed losses, hazards, and constraints that scaffolded this directory are now
superseded by the numbered artifacts above; see those files for the authoritative,
complete sets.
