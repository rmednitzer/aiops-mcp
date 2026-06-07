# Backlog

Stable `BL-NNN` ids. Ids are never renumbered and resolved items are never
deleted (status moves to `resolved`). Each item cites its source ADR. Sizes:
XS, S, M, L.

| ID | Item | Size | Status | Source ADR |
|----|------|------|--------|-----------|
| BL-001 | Add full Apache-2.0 LICENSE text and NOTICE | XS | resolved | 0001 |
| BL-002 | Write ADR-0002..0010 and complete `pyproject.toml` + `Makefile` | S | resolved | 0002 |
| BL-003 | Complete STPA artifacts 01..07 (losses, hazards, constraints, control structure, UCAs, loss scenarios, security constraints) | M | resolved | 0009 |
| BL-004 | Execution core: patterns/policy/redaction/audit/contract/runner (vendored + fused), with invariant tests | L | resolved | 0004, 0005 |
| BL-005 | StoreProtocol + ladder; SQLite default backend (bitemporal, append-only trigger, active-fact constraint, sqlite-vec) | L | resolved | 0002, 0003 |
| BL-006 | Postgres+AGE+pgvector production backend behind the same Protocol | M | resolved | 0002, 0003 |
| BL-007 | Fact model + host_type; osquery and AIDE collectors (read-only) | M | resolved | 0007 |
| BL-008 | Drift engine: desired-state sources (tofu plan, ansible check, known-good) + findings | L | resolved | 0007 |
| BL-009 | Actuation adapters (ssh/opentofu/ansible/runbook/talosctl/redfish/cloud) with DRY_RUN -> approve -> execute | L | resolved | 0004, 0005 |
| BL-010 | Skills engine: manifest, registry, routing-chain dispatcher; eval gate + schema guard | M | resolved | 0010 |
| BL-011 | Tamper-evident audit + evidence: supervisor writer, Merkle, RFC 3161, optional Rekor | M | resolved | 0008 |
| BL-012 | MCP server surface: config, transport guards (stdio/http, SSRF egress, consent), tools with annotations | L | resolved | 0006 |
| BL-013 | CI workflows (codeql, sbom, dependency-review, fuzz; pinned SHAs; least-privilege) + ci-success aggregate | M | resolved | 0001 |
| BL-014 | Hardened deploy: Helm chart, systemd units, optional zarf | M | resolved | 0006 |
| BL-015 | Compliance map: complete EU AI Act / NIS2 / CRA / GDPR / ISO 27001 mapping to controls | S | resolved | 0009 |
| BL-016 | Migration note: import prototype host-knowledge and known-good baselines into the model | S | resolved | 0007 |
| BL-017 | Audit read and ingest tools through the single path (`query_facts`, `fact_history`, `ingest_observation`, `drift_scan` currently bypass `run()`) | S | open | 0011 |
| BL-018 | Write an audit record for trifecta denials before raising `TrifectaViolation` (context + actuate) | S | resolved | 0011, 0013 |
| BL-019 | Include the tool name in the classify/deny probe; document that any future stdin/env passthrough must be classified | S | open | 0011 |
| BL-020 | SSH adapter host-key policy (`StrictHostKeyChecking accept-new`/`yes`, `BatchMode=yes`, `UserKnownHostsFile`) | S | resolved | 0011, 0013 |
| BL-021 | `run_subprocess` process-group isolation (`start_new_session=True` plus `killpg` on timeout) | S | resolved | 0011, 0013 |
| BL-022 | Keep Talos snapshot hash verification on etcd-restore (never pass `--recover-skip-hash-check`; optional sidecar verify) | S | open | 0011 |
| BL-023 | Pre-flight `talosctl health` HARD precondition before talosctl upgrade | S | open | 0011 |
| BL-024 | Runbook actuation by registry id (preferred) or a canonicalised, base-dir-contained path | M | open | 0011 |
| BL-025 | Safe-default destructive scope for talosctl reset (no implicit `--wipe-mode ALL`; `ALL` is T3-confirmed) | S | open | 0011 |
| BL-026 | Finite-or-default numeric parsing of collected host data at every collector site | S | open | 0011 |
| BL-027 | Additive store extension Protocols plus content-hash compare-and-set for supersede | M | open | 0011 |
| BL-028 | Postgres backend engine-level append-only (`REVOKE` plus `BEFORE TRUNCATE` trigger; optional `RESTRICTIVE` RLS floor) | M | open | 0011 |
| BL-029 | Serialise audit hash-chain appends for concurrent writers (process lock now; `pg_advisory_xact_lock` for the PG path) | S | open | 0011 |
| BL-030 | Stamp `raw_snapshot_hash` of each collected snapshot into the Merkle checkpoint | M | open | 0011 |
| BL-031 | Machine-checkable compliance map (bidirectional code/control/article validator plus framework coverage) in CI | M | open | 0011 |
| BL-032 | helm-unittest chart assertions for the praxis chart, gated in CI | M | open | 0011 |
| BL-033 | Supply-chain parity: real zarf digest, CycloneDX SBOM, values/sbom/zarf CI parity, governance-as-code labels | M | open | 0011 |
| BL-034 | Multi-severity `parse_ansible_check` (FAILED to ERROR, unreachable to CRITICAL, ok to known-good) | S | resolved | 0011, 0013 |
| BL-035 | Documented audit/evidence retention tiers bound in config (NIS2 Art. 23, ISO 27001 A.8.15) | S | open | 0011 |
| BL-036 | Governance hygiene bundle (module back-citation headers, agent hard-rules, values-prod overlay plus version-bump checklist, namespace default-deny NetworkPolicy, regulatory-deadline data, empty-string-not-loopback test) | M | open | 0011 |
| BL-037 | `verify_evidence` fail-closed (return, never raise) and require checkpoints to cover the full log; document `LocalStamper` forgeability | M | resolved | 0012 |
| BL-038 | Postgres append-only trigger: guard all identity columns, split per-table (facts vs edges), correct the parity docstring | M | resolved | 0012 |
| BL-039 | Store triggers: block any `t_invalid`/`t_superseded`/`superseded_actor` mutation that leaves a row active (supersede-without-actor bypass) | S | resolved | 0012 |
| BL-040 | Patterns: fix the `chmod`/`chown -R /` deny and the `/etc/` write tier (`\b`-before-`/` defect); bump `PATTERNS_VERSION` | S | resolved | 0012 |
| BL-041 | Redaction: cover space-separated credential flags and URL/DSN credentials; redact the stdio server error path | S | resolved | 0012 |
| BL-042 | SSRF: normalise decimal/hex/octal/trailing-dot IP forms; `assert_egress_allowed` fail-closed on a non-IP host | S | resolved | 0012 |
| BL-043 | OpenTofu DRY_RUN uses a full `tofu plan` so the preview scope matches the apply scope | XS | resolved | 0012 |
| BL-044 | `_bounded_error` never raises, so `run()` always writes exactly one audit record | XS | resolved | 0012 |
| BL-045 | Docs honesty: ADR-0006 consent audit note; qualify `SECURITY.md`/`LIMITATIONS.md`; fix STPA `_ssrf.py` path and read-tool audit claim | S | resolved | 0012 |
| BL-046 | SSRF: resolve hostnames and check every resolved IP (rebinding-aware); wire the filter into the egress path | M | open | 0012 |
| BL-047 | talosctl: enforce the T3 single-target rule on `host.nodes`, not only `host.name` | S | resolved | 0012, 0013 |
| BL-048 | talosctl: replace `action.split()` with a verb allowlist; pass structured params | S | resolved | 0012, 0013 |
| BL-049 | Wire `CredentialBroker` into the actuation path (scoped, revocable enforcement) | M | open | 0012 |
| BL-050 | Audit hash chain: anchored high-water-mark to detect tail truncation | M | open | 0012 |
| BL-051 | Helm NetworkPolicy: restrict ingress with a `from:` selector | S | open | 0012 |
| BL-052 | CI: make CodeQL/fuzz/sbom/dependency-review required gates, not branch-protection-external | S | open | 0012 |
| BL-053 | Add coverage tooling and a `cov-fail-under` gate | S | open | 0012 |
| BL-054 | Store: `_cosine` finite-input guard; `seq` uniqueness or identity column to remove the `MAX(seq)+1` race | S | resolved | 0012, 0013 |
| BL-055 | Audit logger: do not reopen the file after `_degrade`; close the sink on degraded close | S | resolved | 0012, 0013 |
| BL-056 | stdio server: bound the per-line read; correct JSON-RPC notification and batch handling | S | open | 0012 |
| BL-057 | Manifest parser: exact `---` fence, size cap, reject indented keys, reject duplicate keys | S | resolved | 0012, 0013 |
| BL-058 | Collectors: AIDE empty output is not clean; per-collector size caps; finite numeric parse (with BL-026) | S | resolved | 0012, 0013 |
| BL-059 | Drift: escalate `UNEXPECTED` security-predicate findings; split multi-host Ansible subjects | S | resolved | 0012, 0013 |
| BL-060 | Deploy and config: Helm health probes, systemd drop-in dedupe, pin `cyclonedx-bom`, strip whitespace `HTTP_HOST`, normalise compliance-map path citations | M | open | 0012 |
| BL-061 | Test and fuzz wave: Postgres parity suite, evidence tamper matrix, host_type refusal per adapter, SSRF bypass tests, fuzz manifest/merkle/evidence | M | open | 0012 |
| BL-062 | Route read tools (`query_facts`, `fact_history`, collector/skill reads) through the audited path, or formally document the deliberate exclusion; reconcile with invariant 1 wording | S | open | 0012 |
| BL-063 | Actuation subprocess hardening: scrub env (`GIT_TERMINAL_PROMPT=0`, `DEBIAN_FRONTEND=noninteractive`, neutralise `*_ASKPASS`) and detach stdin (`DEVNULL`) so a wrapped tool cannot read the MCP stdio stream or hang on a prompt | S | resolved | 0013 |
| BL-064 | Audit log opened `O_APPEND` and owner-only (`0o600`, plus chmod of a pre-existing file) so redacted parameters are not world/group readable | XS | resolved | 0013 |
| BL-065 | Redaction: add provider token shapes (`github_pat_`, `glpat-`, `npm_`, `AIza`, `ya29.`, Stripe, OpenAI scoped) and make `Authorization` value-complete (no SigV4 signature leak) | S | resolved | 0013 |
| BL-066 | Self-containment: remove the out-of-tree prototype reference from `context.py` (no sibling repo named in code or docs) | XS | resolved | 0013 |
| BL-067 | Config: strip whitespace from `PRAXIS_HTTP_HOST` so a `"127.0.0.1\n"` value is recognised as loopback; empty defaults to loopback (residual of BL-060) | XS | resolved | 0013 |
| BL-068 | Store: add a `seq` identity/uniqueness so the `MAX(seq)+1` read cannot race across two store instances on one file (residual of BL-054) | S | open | 0013 |
