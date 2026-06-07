# AGENTS.md

Short operating spec for `aiops-mcp` (product: `praxis`). The full build brief is
`docs/first-session.md`; the behavior overlay is `CLAUDE.md`.

## One-line

A self-contained, security-first unified AI-operations MCP server: a live
bitemporal fleet model, a drift engine, and a tiered audited actuator.

## Repo map

- `src/praxis/execution/` the single audited, tier-aware execution core
  (patterns, policy, redaction, audit, contract, runner). `patterns.py` is the
  sole security-review file.
- `src/praxis/model/`, `src/praxis/store/` the bitemporal fact model and the
  pluggable store (sqlite default, postgres+age production) behind one Protocol.
- `src/praxis/collectors/`, `src/praxis/drift/` read-only telemetry into facts,
  and observed-vs-desired diffing.
- `src/praxis/actuation/` adapters that wrap ssh/opentofu/ansible/runbooks/
  talosctl/redfish/cloud (DRY_RUN, then approve, then execute).
- `src/praxis/skills/`, `src/praxis/tools/` skills engine and the MCP tool
  surface; `src/praxis/audit/` tamper-evident evidence.
- `docs/adr/`, `docs/stpa/`, `docs/backlog.md`, `docs/governance/` the
  governance-as-code spine.

## Hard rules

1. No imports from or runtime dependency on any other repository. Self-contained.
2. The nine invariants in `CLAUDE.md` are load-bearing. Each has a test.
3. Governance traceability: decisions are ADRs, work is `BL-NNN`, safety and
   security requirements are STPA-derived.
4. `make check` (ruff + mypy strict + pytest) plus the schema and eval gates must
   pass before a change is real.
5. Never weaken a default to make something pass.

## Build and test

- `make check` runs lint + type-check + test. `make schema` regenerates JSON
  Schemas; `make eval` runs the dispatch P@1/MRR gate.
- Optional backends (Postgres+AGE) skip cleanly when absent; the default path is
  SQLite with no external services.
