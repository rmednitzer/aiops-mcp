# 05 Unsafe Control Actions

An Unsafe Control Action (UCA) is a control action that, in a particular context,
is unsafe. STPA considers four modes per action:

- P: provided when it should not be.
- NP: not provided when it should be.
- T: provided in the wrong timing or order.
- D: applied for the wrong duration (stopped too soon, or continued too long).

Every state-changing MCP tool appears below as a control action. Each cell cites
the hazard (`02-hazards.md`) it realizes; "n/a" means the mode is not unsafe for
that action. The covering constraint is in `07-security-constraints.md`.

## Actuation control actions

| Control action (tool) | P (provided wrongly) | NP (not provided) | T (wrong order/timing) | D (wrong duration) |
|-----------------------|----------------------|-------------------|------------------------|--------------------|
| `act_shell` (ssh/shell on ubuntu/windows) | UCA-1 run privileged command without approval or against deny list -> H-1, H-3 | n/a (omission is safe) | UCA-2 execute before audit record committed -> H-2 | UCA-3 long-running command not bounded/truncated -> H-9 |
| `act_ansible` (config apply) | UCA-4 apply playbook without DRY_RUN + approval -> H-1, H-6 | n/a | UCA-5 apply against stale desired-state -> H-6 | n/a |
| `act_opentofu` (infra apply) | UCA-6 apply plan without approval or on many targets at once -> H-1, H-6 | n/a | UCA-7 apply a plan generated against drifted state -> H-6 | n/a |
| `act_runbook` (subprocess) | UCA-8 run a runbook whose tier was under-rated -> H-3 | n/a | UCA-9 run before precondition/audit -> H-2 | n/a |
| `act_talos` (talosctl) | UCA-10 issue destructive talosctl (reset/upgrade) without typed token / one-target -> H-1 | n/a | n/a | n/a |
| `act_talos` against wrong host | UCA-11 SSH path selected for a Talos host -> H-5 | n/a | n/a | n/a |
| `act_redfish` (OOB power/boot) | UCA-12 power/boot change without approval -> H-1 | n/a | UCA-13 power action mistimed (during write) -> H-6 | n/a |
| `act_cloud` (cloud API) | UCA-14 mutate cloud resource without approval / SSRF egress check -> H-1, H-7 | n/a | n/a | n/a |

## Convergence and state control actions

| Control action | P | NP | T | D |
|----------------|---|----|---|---|
| `converge` (apply a drift fix) | UCA-15 converge automatically from a finding (no human gate) -> H-1, H-6 | UCA-16 fail to converge a critical safety drift and not surface it -> H-6, L-5 | UCA-17 converge against a superseded baseline -> H-6 | n/a |
| `supersede_fact` (state write) | UCA-18 supersede with no actor/reason, or mutate in place -> H-10 | n/a | n/a | n/a |
| `delete_fact` (must not exist) | UCA-19 any in-place deletion path -> H-10 | n/a | n/a | n/a |

## Operator and boundary control actions

| Control action | P | NP | T | D |
|----------------|---|----|---|---|
| `approve` (operator confirm) | UCA-20 approval reused across calls / replayed -> H-1 | n/a | UCA-21 approval granted after execution started -> H-2 | UCA-22 approval not bounded to one action, reused on retry -> H-1 |
| `set_mode` | UCA-23 raise mode ceiling silently / per-tool override -> H-1 | n/a | n/a | n/a |
| `kill_switch` | n/a | UCA-24 kill switch does not stop in-flight/new execution -> H-8 | n/a | UCA-25 kill switch auto-clears without operator action -> H-8 |
| `serve_http` (enable network) | UCA-26 bind non-loopback without token + opt-in + SSRF filter -> H-7 | n/a | n/a | n/a |

## Coverage note

Read-only control actions (T0 collectors, queries, skill reads) are not state
changing and are not enumerated here. In v0 the read tools (`query_facts`,
`fact_history`) read the store directly and are not individually audit-logged; the
single audited path (SC-1) covers the execution and actuation tools. Their feedback
is still treated as untrusted (SC-4). Routing reads through the audited path is
tracked as BL-062 (ADR-0012).
