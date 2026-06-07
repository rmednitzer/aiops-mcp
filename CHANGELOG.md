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
- Collectors (BL-007) under `praxis.collectors`: a pure-parser `Collector` base
  plus osquery, AIDE, a generic command probe, and talos collectors that
  normalize untrusted telemetry into observed facts.
- Drift engine (BL-008) under `praxis.drift`: a read-only `diff` (missing /
  changed / unexpected, with severity escalation for security predicates),
  desired-state sources (known-good snapshot, `tofu plan`, `ansible --check`),
  and human-gated `converge` (a finding never auto-fixes; SEC-6). A frozen
  snapshot-vs-known-good regression fixture under `evaluation/drift/` guards the
  diff (DoD).
- Actuation adapters (BL-009) under `praxis.actuation`: an `ActuationAdapter` base
  that wraps a tool, enforces host_type as a HARD audited precondition (SEC-5),
  and routes through the executor (DRY_RUN -> approve -> execute); ssh (never
  Talos), ansible (native `--check` dry run), opentofu (native `plan` dry run),
  talosctl (Talos only), and runbook adapters; a `CredentialBroker` with scoped,
  revocable grants and a kill switch (invariant 9). Tests use PATH-shimmed fakes
  and prove SEC-5.
- MCP server surface (BL-012): `praxis.config` (PRAXIS_ env bound at import) with a
  fail-closed transport guard; `praxis._ssrf` (egress filter blocking loopback,
  link-local, RFC1918, CGNAT; SEC-7); `praxis.context.ServerContext` with the
  lethal-trifecta gate (SEC-4) and classification filtering; a self-contained
  stdio JSON-RPC server (`praxis.server`) with a transport-agnostic tool registry;
  and the tool surface (`query_facts`, `fact_history`, `ingest_observation`,
  `drift_scan`, `run_action`) with accurate readOnly/destructive annotations. The
  CLI (`python -m praxis`) runs over stdio against SQLite with no external
  services and refuses unsafe HTTP binds. All nine invariants now have tests.
- Skills engine (BL-010) under `praxis.skills`: a self-contained SKILL.md
  frontmatter parser (no YAML dependency), a code-free registry (untrusted bundles
  load inert, `allow_contract=False`), and a routing-chain dispatcher (exact then
  lexical, per-link failure containment). Five seed bundles under `skills/`. A
  dispatch P@1/MRR eval gate (`make eval`, `scripts/eval.py`) and a JSON-Schema
  drift guard (`make schema` / `scripts/gen_schema.py --check`, `docs/schema/`),
  both also run by the suite and aggregated into `ci-success`.
- Tamper-evident evidence (BL-011) under `praxis.audit`: an RFC 6962 Merkle tree
  (domain-separated), periodic Merkle checkpoints chained over the audit log, RFC
  3161 stamping behind a fail-closed `Stamper` interface (self-contained
  `LocalStamper` default; real TSA staged), `verify_evidence` (hash chain + Merkle
  + checkpoint chain + token, fail-closed), a session header binding the
  server-binary hash into the trail (wired into server startup), and a
  `scripts/verify_audit.py` CLI.
- CI (BL-013): hardened workflows with SHA-pinned actions and least-privilege
  permissions: `ci` (3.12/3.13 matrix running `make ci-success`), `codeql`,
  `dependency-review`, `sbom` (CycloneDX), and a nightly `fuzz` job driving
  `scripts/fuzz.py` (20k+ iterations over classify/policy/redaction, asserting the
  load-bearing invariants). A `ci-success` aggregate gate depends on the matrix.
- Deploy (BL-014): a hardened Helm chart under `deploy/helm/praxis` (PSA
  restricted, default-deny NetworkPolicy, ServiceAccount with no token automount,
  digest-pinned image, optional hardened runtimeClassName); a `systemd` unit with
  a comprehensive hardening drop-in; and a `zarf.yaml` airgap package. HTTP serving
  is staged behind the enforced transport guard (see `deploy/README.md`).
