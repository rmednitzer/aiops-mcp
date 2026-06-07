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
| BL-010 | Skills engine: manifest, registry, routing-chain dispatcher; eval gate + schema guard | M | pending | 0010 |
| BL-011 | Tamper-evident audit + evidence: supervisor writer, Merkle, RFC 3161, optional Rekor | M | pending | 0008 |
| BL-012 | MCP server surface: config, transport guards (stdio/http, SSRF egress, consent), tools with annotations | L | resolved | 0006 |
| BL-013 | CI workflows (codeql, sbom, dependency-review, fuzz; pinned SHAs; least-privilege) + ci-success aggregate | M | pending | 0001 |
| BL-014 | Hardened deploy: Helm chart, systemd units, optional zarf | M | pending | 0006 |
| BL-015 | Compliance map: complete EU AI Act / NIS2 / CRA / GDPR / ISO 27001 mapping to controls | S | pending | 0009 |
| BL-016 | Migration note: import prototype host-knowledge and known-good baselines into the model | S | pending | 0007 |
