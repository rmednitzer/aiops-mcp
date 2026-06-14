# Deep audit 2026-06-14: findings register

Date: 2026-06-14
Scope: see `00-baseline.md`. Findings from five parallel read-only domain audits and
hands-on adversarial probing. Each cites a `file:line` or a command run this session.
Severities: critical / high / medium / low / info. Disposition: fixed (this pass) /
documented / backlog.

## Headline

No critical or high findings. Six code findings remediated in-pass, each with a
regression test; three documented dispositions; documentation drift corrected. The nine
invariants are each mechanically enforced with a passing test (re-confirmed); STPA
traceability is complete (28/28 UCAs, 10/10 SEC constraints, compliance validator 0
violations).

## Findings

### F-001 [MEDIUM] audit `_canonical` could raise on a hostile `__str__` or a cycle - FIXED
`src/praxis/execution/audit.py`. `_canonical` used `json.dumps(..., default=str)`.
`default=str` calls `str(obj)`, which raises if an arg value has a hostile `__str__`, and
a circular reference raises `ValueError` before `default=` is consulted. Either makes
`AuditLogger.record` raise, breaking invariant 3 ("logger never raises") and the function
docstring's explicit claim. Not reachable from JSON-RPC args (native, acyclic) or via
`redact_args` (depth-capped), but the guarantee must hold by construction.
Fix: added `_safe_str` (a `str` that contains a raising `__str__`) and an `_acyclic`
fallback for circular references; `record` now never raises on any input. Test:
`tests/execution/test_audit_hardening.py::test_record_never_raises_on_hostile_str_or_circular_args`.

### F-006 [MEDIUM] redaction missed Anthropic / HuggingFace / DigitalOcean tokens - FIXED
`src/praxis/execution/redaction.py`. The generic `sk-[A-Za-z0-9]{20,}` pattern stops at
the first hyphen, so `sk-ant-api03-...` (Anthropic) is not matched; `hf_...`
(HuggingFace) and `do[opr]_v1_...` (DigitalOcean) have no pattern. A token of these
shapes carried as a plain value under a non-secret-named key reached the redacted audit
params. Confirmed by probe (all three leaked pre-fix; all redacted post-fix). The
Anthropic gap is notable for an MCP server that may handle Claude API keys.
Fix: added explicit value patterns (Anthropic before the generic `sk-`). Test:
`tests/execution/test_redaction.py::test_anthropic_huggingface_digitalocean_tokens_redacted`.

### F-007 [MEDIUM] `supersede` returned a false success to a concurrent loser - FIXED
`src/praxis/store/sqlite.py`, `src/praxis/store/postgres.py`. `supersede` called
`get_active` outside the write, then `UPDATE ... WHERE fact_id = ? AND t_superseded IS
NULL` without checking the rowcount, then re-SELECTed and returned the row. Two concurrent
supersedes of the same fact: the first wins; the second matches 0 rows but still returned
the (now superseded) row carrying the first caller's actor/reason, falsely reporting the
second caller's supersede as the winner. Data integrity held (the append-only trigger and
the WHERE clause prevent a double-supersede), but provenance fidelity did not (SEC-10).
Fix: both backends check the UPDATE rowcount and return `None` on a lost race. Test:
`tests/store/test_store_hardening.py::test_supersede_reports_a_lost_race_as_none`.

### F-004 [LOW] `rm -rf /` deny missed `//`, `/*`, `/.` - FIXED
`src/praxis/execution/patterns.py:57`. The deny pattern matched `rm -rf /` but not the
root-equivalent spellings `rm -rf //` (kernel-normalised to `/`), `rm -rf /*` (glob over
the root), or `rm -rf /.`. These were caught at T3 (recursive `rm`), so they were
approval-gated, not freely runnable, but a deny-wall miss is a gap. Confirmed by probe.
Fix: widened the pattern to `/{1,2}[.*]?`; `rm -rf /etc` is not over-matched (a real path
char follows). Bumped `PATTERNS_VERSION` 3 to 4. Test:
`tests/execution/test_patterns.py::test_deny_catches_root_wipe_and_forkbomb`.

### F-008 [LOW] Talos collector stored unbounded non-JSON text - FIXED
`src/praxis/collectors/talos.py:33`. When `talosctl` output was not valid JSON, the full
stripped raw string was stored as `{"status": raw}` with no length cap. A hostile or
malfunctioning node could push up to the 4 MiB tool-output ceiling into the bitemporal
fact store every collection cycle (storage exhaustion; untrusted-data hygiene, inv 8).
Fix: cap the fallback at 4096 chars with a truncation marker. Test:
`tests/collectors/test_collectors.py::test_talos_non_json_status_is_capped`.

### F-003 [LOW] OpenTofu passed an unconfined `chdir` - FIXED
`src/praxis/actuation/opentofu.py:27`. `chdir = params.get("chdir")` was interpolated as
`-chdir=<value>` with no `confine_to_root`, unlike the Ansible/runbook adapters. Dead
code today (`chdir` is not a `RunActionArgs` field, so it is unreachable via the MCP
layer), but a latent unconfined path-traversal vector for any future extension.
Fix: removed the unconfined passthrough. Safe re-add (a `PRAXIS_TOFU_ROOT`-confined
`chdir`) tracked as BL-105. Test:
`tests/actuation/test_adapters.py::test_opentofu_ignores_unconfined_chdir`.

## Documented dispositions (no code behaviour change)

### F-002 [LOW/INFO] redaction is pattern-based - DOCUMENTED
An unkeyed high-entropy secret in no recognised format is not redacted (confirmed:
`Zx9Q`*10 passes through). This is by design. Documented in `SECURITY.md`: the
load-bearing controls are that output bodies are never logged and secret-named keys are
always redacted; curated value patterns are extended as new shapes appear (BL-097/F-006).

### F-005 [MEDIUM->disposed] syslog destination is not SSRF-filtered - DOCUMENTED
`SyslogAuditSink._connect` does not run `PRAXIS_AUDIT_SYSLOG_ADDRESS` through the SSRF
egress filter, unlike the RFC 3161 TSA URL. This is intended: the syslog address is
operator-supplied deploy configuration, not a model- or attacker-influenced destination,
and a local SIEM on an RFC1918 / CGNAT / Tailscale address is the normal case, which the
SSRF filter (blocks all private ranges) would break. The records are already redacted.
Documented in the `SyslogAuditSink` docstring, `operate.md`, and the ADR-0037 audit note.
The TSA URL is filtered because it targets a public service where a private resolution is
anomalous; the distinction is now explicit.

### F-009 [LOW] ADR-0015 lacked a ratification note - DOCUMENTED
ADR-0015 (Proposed) was ratified by ADR-0016 but lacked the appended ratification note
that ADR-0024/0029 carry. Added (the decision body is unchanged; ADRs are immutable).

## Deferred hardening (backlog)

- BL-105 OpenTofu workspace selection via a `PRAXIS_TOFU_ROOT`-confined `chdir` (F-003).
- BL-106 timing-safe (`secrets.compare_digest`) approval-token comparison before any
  network-accessible submission path; prerequisite of the HTTP transport (BL-012).
- BL-107 a total-message-byte cap for the stdio reader before a multi-client transport.
- BL-108 per-pair / per-value caps in `CommandProbeCollector.parse` (untrusted data).
- BL-109 make `compliance-controls.json` proving-test lists exhaustive vs representative.

## Lower-severity observations folded into the above or noted only

- Approval-token comparison timing (info): tracked as BL-106.
- `_drain_line` unbounded per-message iteration (info, single-client stall only): BL-107.
- Postgres `_SCHEMA` DROP+CREATE trigger window: atomic within the schema transaction and
  never externally observable; left as-is (a comment improvement, not a defect).
- `LocalStamper` forgeability: already documented (`SECURITY.md`); OS append-only is the
  stated control. No action.
- Stale BL-103 comment in `postgres.py` (BL-103 now resolved): corrected in-pass.

## Validated solid (re-confirmed, with enforcing tests)

- Invariant 1 single audited path: every tool routes through `run_audited` -> `run`;
  `tests/test_audited_reads.py`, `tests/execution/test_runner.py`.
- Invariant 2 tier round-up / global deny: `classify = max(base, command_tier)`, deny
  first; `tests/execution/test_policy.py`, `test_patterns.py`.
- Invariant 3 audit (hash chain, no body, never raises, redact-first): `test_audit.py`,
  `test_audit_hardening.py`, `test_redaction.py` (plus F-001 hardening).
- Invariant 4 bitemporal append-only (delete/update blocked at engine, one active fact,
  CAS race-safe): `tests/store/test_append_only.py`, `test_store_hardening.py`.
- Invariant 5 host_type gate (never SSH a Talos host): `tests/actuation/test_host_type_gate.py`.
- Invariant 6 DRY_RUN->approve->execute, T3 single target + typed token:
  `tests/execution/test_runner.py`, `tests/actuation/test_hardening.py`,
  `tests/drift/test_converge_gate.py`.
- Invariant 7 transport guard + SSRF (encoded IPs, IPv4-mapped, 6to4, rebinding):
  `tests/test_transport_guard.py`; probe matrix in `00-baseline.md`.
- Invariant 8 trifecta containment + untrusted collected data: `tests/test_trifecta_containment.py`,
  `tests/collectors/test_numeric_hardening.py`.
- Invariant 9 kill switch, scoped credentials, env scrubbing, no NOPASSWD ALL:
  `tests/execution/test_kill_switch.py`, `tests/actuation/test_hardening.py`.
- STPA: 28/28 UCAs covered, 10/10 SEC constraints enforced, compliance validator 0
  violations (11 rules); all 38 prior ADRs consistent; 15 spot-checked backlog items
  confirmed implemented.
