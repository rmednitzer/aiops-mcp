# 07 Security constraints

Each security constraint refines a system-level constraint (`03-system-constraints.md`),
prevents one or more UCAs (`05-ucas.md`), mitigates a loss scenario
(`06-loss-scenarios.md`), and maps to a concrete enforcement mechanism (a code
assertion, a policy rule, or a HITL gate) with a test that proves it. This is the
load-bearing traceability table required by ADR-0009.

| ID | Constraint | Parent SC | Prevents (UCA) | Mitigates (LS) | Enforcement mechanism (code/policy/gate) | Proving test | Invariant |
|----|-----------|-----------|----------------|----------------|------------------------------------------|--------------|-----------|
| SEC-1 | The deny list is global and unconditional, evaluated before tier gating, in every mode. | SC-3 | UCA-1 | LS-1 | `execution/policy.py::Policy.check` (deny-first branch) | `tests/execution/test_policy.py::test_deny_is_global_and_first` | 2 |
| SEC-2 | Exactly one ordered execution pipeline; every call (success, failure, denial) writes an audit record; approval binds to one action and a retry needs fresh approval. | SC-1, SC-2 | UCA-2, UCA-9, UCA-20, UCA-21, UCA-22 | LS-2, LS-9 | `execution/runner.py::run` (fixed pipeline); `execution/contract.py` (approval, one retry) | `tests/execution/test_runner.py::test_pipeline_order_and_audit_always`, `::test_retry_requires_fresh_approval` | 1 |
| SEC-3 | classify rounds up on ambiguity; sudo/doas/pkexec are at least T2. | SC-3 | UCA-1, UCA-8 | LS-1 | `execution/patterns.py` (regex set + `PATTERNS_VERSION`); `execution/policy.py::classify` | `tests/execution/test_patterns.py::test_priv_escalation_is_at_least_t2`, `::test_classify_rounds_up` | 2 |
| SEC-4 | A session never holds sensitive data + untrusted content + actuation without a human gate; read tools are separable from act tools; collected data is untrusted. | SC-4 | UCA-1, UCA-15 | LS-6 | `context.py` (read/act separation, phase gate, audited refusal); tool annotations; `tools/` split read vs act | `tests/test_trifecta_containment.py::test_act_requires_gate_after_untrusted_read`, `tests/test_actuate_trifecta.py::test_trifecta_denial_is_audited` | 8 |
| SEC-5 | Actuation branches on host_type; SSH is refused for a Talos host; SSH carries a host-key policy and an option-injection-safe target; talosctl is verb-allowlisted and node-aware at T3 (ADR-0013). | SC-5 | UCA-11 | LS-4 | `actuation/*` host_type assertion; `actuation/ssh.py` Talos refusal + `StrictHostKeyChecking`/`BatchMode`; `actuation/talosctl.py` verb allowlist + node target | `tests/actuation/test_host_type_gate.py::test_ssh_refuses_talos`, `tests/actuation/test_hardening.py::test_ssh_argv_carries_host_key_policy`, `::test_talosctl_t3_refuses_multiple_nodes` | 5 |
| SEC-6 | Convergence is DRY_RUN -> approve -> execute; no finding auto-fixes; the target and baseline currency are validated. | SC-6 | UCA-15, UCA-16, UCA-17 | LS-3 | `drift/converge.py` (request object, no auto-apply); `actuation` DRY_RUN gate | `tests/drift/test_converge_gate.py::test_finding_does_not_autofix`, `::test_converge_requires_dry_run_then_approval` | 6 |
| SEC-7 | stdio by default; any non-loopback bind requires token AND explicit opt-in AND an SSRF egress filter; no token passthrough. | SC-7 | UCA-26, UCA-14 | LS-5 | `server.py` transport guard; `config.py`; SSRF egress filter (`src/praxis/_ssrf.py`) | `tests/test_transport_guard.py::test_http_refuses_nonloopback_without_optin`, `::test_ssrf_blocks_private_ranges` | 7 |
| SEC-8 | Credentials are scoped, revocable, never logged; the kill switch stops execution immediately and clears only by operator action; logger construction never raises; an actuation subprocess is process-group isolated with a scrubbed environment and detached stdin (ADR-0013). | SC-8 | UCA-24, UCA-25 | LS-9, LS-2 | `execution/runner.py` kill-switch check; credential scoping in `actuation`; `execution/audit.py` degrade-to-stderr; `actuation/base.py` `start_new_session`/`killpg`/`DEVNULL`/env scrub | `tests/execution/test_kill_switch.py::test_kill_switch_blocks_execution`, `tests/execution/test_audit.py::test_logger_never_raises`, `tests/actuation/test_hardening.py::test_run_subprocess_kills_process_group_on_timeout` | 9, 3 |
| SEC-9 | The audit log stores output_sha256 + output_len only, never bodies; parameters are redacted; output is truncated; the log file is owner-only (ADR-0013). | SC-9 | UCA-3 | LS-8 | `execution/audit.py` (hash + length record, `0o600` `O_APPEND` sink); `execution/redaction.py` | `tests/execution/test_audit.py::test_no_body_only_hash_and_len`, `tests/execution/test_audit.py::test_audit_file_is_owner_only`, `tests/execution/test_redaction.py::test_secrets_redacted` | 3 |
| SEC-10 | State facts are append-only; deletion is blocked at the storage layer; supersession carries actor + reason; one active fact per (subject, predicate, fact_type). | SC-10 | UCA-18, UCA-19 | LS-7 | `store/sqlite.py` delete-blocking trigger + active-fact unique index; `store/base.py` Protocol (no delete) | `tests/store/test_append_only.py::test_delete_is_blocked`, `::test_supersede_requires_actor_and_reason` | 4 |

## How to read this table

- A new state-changing tool MUST add a UCA row (`05-ucas.md`) and either fall
  under an existing SEC constraint here or add a new one with its enforcement and
  test. A tool with no covering constraint is a visible gap.
- "Enforcement mechanism" names the file (and where stable, the symbol) that
  realizes the constraint. "Proving test" names the test that fails if the
  enforcement regresses.
- The "Invariant" column ties each constraint back to the nine invariants in
  `CLAUDE.md`, so the invariant set and the STPA derivation stay one analysis.
