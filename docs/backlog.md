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
| BL-018 | Write an audit record for trifecta denials before raising `TrifectaViolation` (context + actuate) | S | open | 0011 |
| BL-019 | Include the tool name in the classify/deny probe; document that any future stdin/env passthrough must be classified | S | open | 0011 |
| BL-020 | SSH adapter host-key policy (`StrictHostKeyChecking accept-new`/`yes`, `BatchMode=yes`, `UserKnownHostsFile`) | S | open | 0011 |
| BL-021 | `run_subprocess` process-group isolation (`start_new_session=True` plus `killpg` on timeout) | S | open | 0011 |
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
| BL-034 | Multi-severity `parse_ansible_check` (FAILED to ERROR, unreachable to CRITICAL, ok to known-good) | S | open | 0011 |
| BL-035 | Documented audit/evidence retention tiers bound in config (NIS2 Art. 23, ISO 27001 A.8.15) | S | open | 0011 |
| BL-036 | Governance hygiene bundle (module back-citation headers, agent hard-rules, values-prod overlay plus version-bump checklist, namespace default-deny NetworkPolicy, regulatory-deadline data, empty-string-not-loopback test) | M | open | 0011 |
