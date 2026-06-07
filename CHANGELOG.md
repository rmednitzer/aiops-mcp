# Changelog

All notable changes to this project are documented here. Format follows Keep a
Changelog; the project uses semantic versioning once it reaches a tagged release.

## [Unreleased]

### Added
- Governance-first bootstrap scaffold: repository layout, `CLAUDE.md`,
  `AGENTS.md`, `README.md`, `SECURITY.md`, `LIMITATIONS.md`, `CONTRIBUTING.md`.
- `docs/first-session.md` (the build brief), ADR-0001 and the ADR index,
  the `docs/stpa/` skeleton, `docs/backlog.md` seed, the compliance-map skeleton,
  and a seed fleet inventory example.
- Baseline `pyproject.toml`, `Makefile`, `.gitignore`, and a CI workflow skeleton.
- Governance step 0 (BL-001, BL-002, BL-003): full Apache-2.0 `LICENSE` text;
  ADR-0002 through ADR-0010 (store strategy, bitemporal facts, tiered authority,
  execution trust boundary, MCP transport/auth, drift engine, tamper-evident
  audit, STPA method, skills architecture), all Accepted; the complete STPA
  analysis `docs/stpa/01..07` with the SEC-1..SEC-10 traceability table mapping
  every security constraint to an enforcement mechanism and a proving test.
- Execution core (BL-004): the single audited execution path under
  `praxis.execution` (patterns, policy, redaction, audit, contract, runner) with
  invariant tests for SEC-1/2/3/8/9.
- Bitemporal fact model (BL-005) under `praxis.model`: `Fact`, `Edge`, the
  `HostType` enum, and the four timestamps (ADR-0003).
- Store (BL-005, BL-006): `StoreProtocol` plus an extension ladder
  (`VectorStore`); a default SQLite backend with storage-layer append-only
  triggers, the active-fact unique index, supersession with actor and reason, and
  a pure-Python vector search; a Postgres+AGE backend behind the same Protocol
  (lazy `psycopg`; skip-tested where no live PG exists). Tests cover round-trip,
  bitemporal history, and append-only (SEC-10).
