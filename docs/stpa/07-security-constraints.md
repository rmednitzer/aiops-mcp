# 07 Security constraints

Each security constraint refines a system-level constraint (`03-system-constraints.md`),
prevents one or more UCAs (`05-ucas.md`), mitigates a loss scenario
(`06-loss-scenarios.md`), and maps to a concrete enforcement mechanism (a code
assertion, a policy rule, or a HITL gate) with a test that proves it. This is the
load-bearing traceability table required by ADR-0009.

| ID | Constraint | Parent SC | Prevents (UCA) | Mitigates (LS) | Enforcement mechanism (code/policy/gate) | Proving test | Invariant |
|----|-----------|-----------|----------------|----------------|------------------------------------------|--------------|-----------|
| SEC-1 | The deny list is global and unconditional, evaluated before tier gating, in every mode. | SC-3 | UCA-1 | LS-1 | `execution/policy.py::Policy.check` (deny-first branch) | `tests/execution/test_policy.py::test_deny_is_global_and_first` | 2 |
| SEC-2 | Exactly one ordered execution pipeline; every tool call, read or write (success, failure, denial), writes an audit record; approval is a server-minted, single-use, TTL-bound nonce bound to one action/target/tier/ruleset and surfaced out-of-band; a retry needs a fresh one (ADR-0016). | SC-1, SC-2 | UCA-2, UCA-4, UCA-6, UCA-9, UCA-10, UCA-20, UCA-21, UCA-22, UCA-27; UCA-12, UCA-13, UCA-14 (planned adapters) | LS-2, LS-9 | `execution/runner.py::run` (fixed pipeline, mint on gated DRY_RUN); `execution/contract.py::ApprovalRegistry` (mint/validate/consume); `tools/_audited.py` (reads and ingest routed through the path) | `tests/execution/test_runner.py::test_pipeline_order_and_audit_always`, `::test_retry_requires_fresh_approval`, `::test_caller_cannot_forge_an_approval`, `tests/test_audited_reads.py::test_every_tool_writes_an_audit_record` | 1 |
| SEC-3 | classify rounds up on ambiguity; sudo/doas/pkexec are at least T2; the server-wide mode ceiling (open/guarded/readonly) gates which tiers may run and cannot be raised silently or overridden per tool (ADR-0022). | SC-3 | UCA-1, UCA-8, UCA-23 | LS-1 | `execution/patterns.py` (regex set + `PATTERNS_VERSION`); `execution/policy.py::classify` and the `Policy.check` mode gate | `tests/execution/test_patterns.py::test_priv_escalation_is_at_least_t2`, `::test_classify_rounds_up`; `tests/execution/test_policy.py::test_mode_ceiling_cannot_be_escalated_per_tool` | 2 |
| SEC-4 | A session never holds sensitive data + untrusted content + actuation without a human gate; read tools are separable from act tools; collected data is untrusted, including observed facts read back from the store (ADR-0016). | SC-4 | UCA-1, UCA-15, UCA-28 | LS-6 | `execution/runner.py` (in-path trifecta gate keyed off the shared `SessionTaint` latch, armed before execute); `context.py` (latch delegation, read/act separation); tool annotations; `tools/` split read vs act | `tests/test_trifecta_containment.py::test_act_requires_gate_after_untrusted_read`, `tests/test_actuate_trifecta.py::test_trifecta_denial_is_audited`, `tests/execution/test_runner.py::test_tainted_session_gates_t1_actuation_in_path`, `tests/test_audited_reads.py::test_reading_observed_facts_arms_the_latch` | 8 |
| SEC-5 | Actuation branches on host_type; SSH is refused for a Talos host; SSH carries a host-key policy and an option-injection-safe target; talosctl is verb-allowlisted and node-aware at T3, including the additive `system_labels` partition-scoped reset (ADR-0013, ADR-0021). | SC-5 | UCA-10, UCA-11 | LS-4 | `actuation/*` host_type assertion; `actuation/ssh.py` Talos refusal + `StrictHostKeyChecking`/`BatchMode`; `actuation/talosctl.py` verb allowlist + node target + `--system-labels-to-wipe` scope | `tests/actuation/test_host_type_gate.py::test_ssh_refuses_talos`, `tests/actuation/test_hardening.py::test_ssh_argv_carries_host_key_policy`, `::test_talosctl_t3_refuses_multiple_nodes`, `::test_talosctl_partition_reset_still_classifies_t3` | 5 |
| SEC-6 | Convergence is DRY_RUN -> approve -> execute; no finding auto-fixes; the target and baseline currency are validated. | SC-6 | UCA-4, UCA-5, UCA-6, UCA-7, UCA-15, UCA-16, UCA-17 | LS-3 | `drift/converge.py` (request object, no auto-apply); `actuation` DRY_RUN gate | `tests/drift/test_converge_gate.py::test_finding_does_not_autofix`, `::test_converge_requires_dry_run_then_approval` | 6 |
| SEC-7 | stdio by default; any non-loopback bind requires token AND explicit opt-in AND an SSRF egress filter; no token passthrough. | SC-7 | UCA-26, UCA-14 (planned act_cloud adapter) | LS-5 | `server.py` transport guard; `config.py`; SSRF egress filter (`src/praxis/_ssrf.py`) | `tests/test_transport_guard.py::test_http_refuses_nonloopback_without_optin`, `::test_ssrf_blocks_private_ranges` | 7 |
| SEC-8 | Credentials are scoped, revocable, never logged; the kill switch stops execution immediately, has an operator actuator (`emergency_stop`, a durable file sentinel), and clears only by operator action; logger construction never raises; an actuation subprocess is process-group isolated with an allowlisted environment and detached stdin (ADR-0013, ADR-0016). | SC-8 | UCA-24, UCA-25 | LS-9, LS-2 | `execution/runner.py` kill-switch check + sentinel; `tools/emergency.py` (operator actuator); `actuation/credentials.py` broker scan wired as a HARD precondition in `tools/actuate.py`; `execution/audit.py` degrade-to-stderr; `actuation/base.py` `start_new_session`/`killpg`/`DEVNULL`/env allowlist | `tests/execution/test_kill_switch.py::test_kill_switch_blocks_execution`, `::test_kill_switch_sentinel_is_durable_and_out_of_band`, `::test_emergency_stop_tool_trips_and_is_audited`, `tests/test_audited_reads.py::test_first_grant_flips_actuation_to_deny_unless_authorized`, `tests/execution/test_audit.py::test_logger_never_raises`, `tests/actuation/test_hardening.py::test_run_subprocess_kills_process_group_on_timeout` | 9, 3 |
| SEC-9 | The audit log stores output_sha256 + output_len only, never bodies; parameters are redacted; output is truncated; the log file is owner-only (ADR-0013). | SC-9 | UCA-3 | LS-8 | `execution/audit.py` (hash + length record, `0o600` `O_APPEND` sink); `execution/redaction.py` | `tests/execution/test_audit.py::test_no_body_only_hash_and_len`, `tests/execution/test_audit.py::test_audit_file_is_owner_only`, `tests/execution/test_redaction.py::test_secrets_redacted` | 3 |
| SEC-10 | State facts are append-only; deletion is blocked at the storage layer; supersession carries actor + reason; one active fact per (subject, predicate, fact_type); an optional content-hash compare-and-set forecloses a lost update on a stale read (ADR-0021). | SC-10 | UCA-18, UCA-19 | LS-7 | `store/sqlite.py` delete-blocking trigger + active-fact unique index; `store/base.py` Protocol (no delete) + `VersionedStore` content-hash `put_fact_if` | `tests/store/test_append_only.py::test_delete_is_blocked`, `::test_supersede_requires_actor_and_reason`, `tests/store/test_store_hardening.py::test_compare_and_set_serialises_concurrent_writers` | 4 |

## How to read this table

- A new state-changing tool MUST add a UCA row (`05-ucas.md`) and either fall
  under an existing SEC constraint here or add a new one with its enforcement and
  test. A tool with no covering constraint is a visible gap.
- "Enforcement mechanism" names the file (and where stable, the symbol) that
  realizes the constraint. "Proving test" names the test that fails if the
  enforcement regresses.
- The "Invariant" column ties each constraint back to the nine invariants in
  `CLAUDE.md`, so the invariant set and the STPA derivation stay one analysis.
- Planned-adapter UCAs are pre-staged, not omitted. `act_redfish` (UCA-12, UCA-13)
  and `act_cloud` (UCA-14) have no adapter yet (`05-ucas.md` marks the rows
  planned); their constraints appear above flagged `(planned ...)` so the
  UCA-to-SEC link exists before the code lands. When an adapter is implemented it
  routes through the single audited path (SEC-2 approval and pipeline order), the
  host_type gate (SEC-5), and, for cloud egress, the SSRF filter (SEC-7), and the
  flag is removed.

Machine-checked since 2026-06-13 (ADR-0021): the SEC to
enforcement-module to proving-test to invariant traceability in this table is
projected into `docs/governance/compliance-controls.json` and verified in CI by
`scripts/validate_compliance.py` (BL-031). A SEC constraint with no catalog control,
an enforcement module that does not carry its `SEC-N` back-citation token, a
dangling `SEC-N` token in the source tree, an uncovered regulatory framework, or a
missing proving test now breaks the build.

Enforcement-status caveat (updated 2026-06-14, ADR-0022): the ADR-0015 enforcement
gaps in this table are closed. The single audited path covers every registered tool
including the read tools and `ingest_observation` (BL-017, BL-062, BL-085); the
approval is a server-minted, single-use, TTL-bound nonce surfaced out-of-band
(BL-072, BL-084); the `BudgetTracker` and `CredentialBroker` are wired and the kill
switch has an operator actuator with a durable file sentinel (BL-049, BL-074,
BL-075). The STPA UCA coverage is complete (BL-089, ADR-0022): every UCA-1..28
appears in a SEC "Prevents" column, with the planned `act_redfish`/`act_cloud` UCAs
(UCA-12/13/14) pre-staged and flagged. The remaining known gap: SEC-9's runtime
Merkle checkpoints and anchored high-water mark are produced (BL-076, ADR-0019),
but the keyless `LocalStamper` is still forgeable; a non-forgeable RFC 3161/Rekor
anchor is tracked as BL-095, with operating-system append-only storage the
documented required control until then.
