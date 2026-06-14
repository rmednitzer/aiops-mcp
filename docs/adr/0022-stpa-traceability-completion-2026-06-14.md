# ADR-0022: STPA traceability completion (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (governance traceability completion; resolves ADR-0015 finding BL-089)

## Context

ADR-0015 (finding 089) recorded a governance-traceability gap rather than a code
defect: eight Unsafe Control Actions appeared in no SEC "Prevents" column in
`docs/stpa/07-security-constraints.md`, two planned actuation adapters had UCA rows
but no implementation and no "planned" marking, and the `set_mode` escalation
concern (UCA-23) had no proving test. The STPA tables are load-bearing here
(ADR-0009): a UCA with no covering SEC constraint is a visible gap, and since
ADR-0021 the SEC-to-module-to-test-to-invariant traceability is machine-checked in
CI (`scripts/validate_compliance.py`, BL-031). The UCA-to-SEC coverage itself is
not yet machine-checked, so it had drifted as adapters and tools were added.

The eight uncovered UCAs split three ways:

- The DRY_RUN-then-approve actuation UCAs (UCA-4, UCA-5 for `act_ansible`; UCA-6,
  UCA-7 for `act_opentofu`; UCA-10 for `act_talos`) are already enforced. They were
  simply not listed under their covering constraints (SEC-6 human-gated convergence
  and baseline currency; SEC-2 minted approval and pipeline order; SEC-5 talosctl
  node-aware T3 one-target rule).
- The `set_mode` escalation UCA (UCA-23) concerns the server-wide mode ceiling
  (`open`/`guarded`/`readonly`), the third clause of invariant 2. There is no
  runtime `set_mode` tool: the mode is bound once at startup (`config.mode`,
  `PRAXIS_MODE`) and `execution/policy.py::Policy.check` applies it uniformly to
  every tool, before the tier and approval gates. The escalation surface is "raise
  the ceiling silently" or "override it per tool", and both are foreclosed by
  construction, but no test asserted it.
- The planned-adapter UCAs (UCA-12, UCA-13 for `act_redfish`; UCA-14 for
  `act_cloud`) belong to adapters that do not exist in this version (only a `CLOUD`
  host_type and a redfish deny/classify pattern exist). Their UCA rows pre-date the
  code.

## Decision

1. Complete the UCA-to-SEC coverage in `07-security-constraints.md` so every
   UCA-1..28 appears in a SEC "Prevents" column: UCA-4/UCA-6/UCA-10 added to SEC-2;
   UCA-4..UCA-7 to SEC-6; UCA-10 to SEC-5; UCA-23 to SEC-3. No new SEC constraint is
   minted and no module citation changes, so the ADR-0021 validator stays green
   (the SEC set still equals the STPA set, R3).

2. Cover UCA-23 under SEC-3 (tiered authority, invariant 2) rather than a new
   constraint: the mode ceiling is part of the same tiered-authority enforcement in
   `policy.py`, which already carries the `SEC-3` back-citation token. SEC-3's
   statement is extended (in the STPA table and the compliance catalog) to name the
   mode ceiling explicitly, and a back-citation comment is added at the mode-gate
   site in `Policy.check`. A new proving test,
   `tests/execution/test_policy.py::test_mode_ceiling_cannot_be_escalated_per_tool`,
   asserts that no tool name, command, or declared `base_tier` lifts a call past the
   ceiling, that a mode refusal is a hard refusal (`denied` and `requires_approval`
   both False, so no minted nonce can satisfy it), and that the ceiling is
   server-wide (no per-tool exemption). The test is registered in SEC-3's catalog
   `proving_tests` so the CI validator enforces its existence (R9).

3. Pre-stage the planned-adapter UCAs rather than delete the rows: mark the
   `act_redfish` and `act_cloud` rows `[planned]` in `05-ucas.md`, and flag UCA-12,
   UCA-13, UCA-14 `(planned ...)` where they appear in the SEC "Prevents" columns
   (SEC-2 for the approval and pipeline-order coverage, SEC-7 for the cloud SSRF
   egress check). The flags clear when the adapters are implemented and route through
   the audited path. Keeping the UCA registry ahead of the code means a new adapter
   inherits its constraint instead of shipping uncovered.

This change adds no runtime behavior: the enforcement it documents already existed.
The one code change is the SEC-3 back-citation comment in `policy.py`.

## Consequences

Positive: the STPA derivation regains end-to-end coverage (every UCA maps to a
covering SEC constraint with a proving test), closing the last governance finding
from the ADR-0015 review; the mode ceiling now has an explicit anti-escalation test;
planned adapters carry their constraints before their code, so the UCA registry
leads implementation rather than trailing it.

Negative: the UCA-to-SEC coverage is documented and test-anchored but not yet
machine-checked the way the SEC-to-module-to-test links are; a future UCA could be
added without a covering SEC and only a human reviewer would catch it. Extending the
validator with a UCA-coverage rule is the natural follow-up and is noted as a revisit
trigger.

Neutral: ADR-0015's finding table is left as the immutable snapshot of that review
(its sibling findings, though resolved, also remain marked "open" there); the living
status moves in `docs/backlog.md` (BL-089 resolved) per the established convention.

## Alternatives considered and rejected

- Mint a new SEC constraint for the mode ceiling (UCA-23). Rejected: the mode
  ceiling is the third clause of invariant 2, already enforced in the SEC-1/SEC-3
  policy module; a parallel constraint would split one analysis and force a catalog,
  schema, and back-citation churn for no new enforcement. Extending SEC-3 keeps the
  invariant and its derivation as one.
- Delete the planned-adapter UCA rows until the adapters land. Rejected: the UCA
  table is the registry that a new state-changing tool must extend; removing the
  rows would let `act_redfish`/`act_cloud` ship without a pre-existing constraint,
  the exact gap this ADR closes. Flagging them `[planned]` keeps the registry honest
  and ahead of the code.
- Add a runtime `set_mode` tool to make UCA-23 a live control action. Rejected:
  out of scope and a new escalation surface; the mode is a startup ceiling by
  design (ADR-0004), and the safer property is that there is no runtime raise at all.

## Revisit triggers

- A new state-changing tool or actuation adapter is added (the `[planned]` adapters
  land, or another is introduced): its UCA rows and SEC coverage must be added in the
  same change, and the relevant `(planned)` flags cleared.
- The compliance validator (BL-031) is extended to machine-check UCA-to-SEC
  coverage, at which point this prose mapping becomes a CI-enforced rule.
- A later review finds a UCA-to-SEC mapping here unsound (append an audit note;
  never rewrite a resolved row).
