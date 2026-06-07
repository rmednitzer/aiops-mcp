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
- Governance docs (BL-015, BL-016): a complete compliance map (EU AI Act, NIS2 /
  NISG 2026, CRA, GDPR, ISO 27001) tracing each article through a SEC constraint to
  the enforcing code; a migration note for importing the prototype's host-knowledge
  and known-good baselines into the model; and operate + periodic self-audit
  runbooks under `docs/runbooks/`.

### Security
- Trifecta gate (SEC-4) on `run_action` now requires a VALIDATED, single-use
  approval for a sub-T2 act after untrusted ingestion: the handler validates and
  consumes the `approval_token` against `expected_token` rather than treating mere
  token presence as the human gate. A bare, caller-supplied string can no longer
  bypass containment. A dry run surfaces the `action_id` and the exact
  `approval_token`, so the DRY_RUN -> approve -> execute flow stays operable. New
  `tests/test_actuate_trifecta.py` proves the closed bypass and single-use replay.
- `ServerContext.filter_restricted` now also drops rows whose `classification` sits
  nested inside the fact `value` payload (the shape the state tools emit), and
  `fact_history` applies the filter, so restricted facts cannot leak over HTTP with
  `allow_restricted=false`.
- `PRAXIS_HTTP_PORT` is parsed defensively (`_safe_int`) so a non-numeric value can
  no longer raise at import and bypass the fail-closed transport path;
  `validate_transport` rejects an out-of-range port (1-65535).
- CodeQL tuned to the `security-extended` query suite (drops style/quality advisory
  noise already covered by ruff + mypy strict).
- Internal deep-audit remediation (ADR-0012, BL-037 to BL-045); each fix ships with
  a regression test:
  - `verify_evidence` is fail-closed: it returns `ok=False` (never raises) on
    malformed evidence, and rejects a checkpoint that under-covers or over-claims
    the audit log, so a forged `tree_size` cannot hide records. `LocalStamper`
    token forgeability is now documented (BL-037, with the anchored high-water-mark
    tracked as BL-050).
  - The Postgres append-only triggers are split per table and guard every identity
    and provenance column (facts and edges), matching the SQLite backend; the
    parity docstring is corrected (BL-038).
  - Both store backends block any UPDATE that leaves a row active, so a `t_invalid`
    or `superseded_actor` only mutation can no longer retire a fact without a
    supersede actor and reason (BL-039).
  - A recursive `chmod`/`chown` of `/` is now denied, and writes under `/etc/` via
    `cp`/`mv`/`tee`/`truncate`/`chmod`/`chown`/`ln` classify at least T2 (the
    word-boundary defect that let a space before `/etc/` fall to T0 is fixed).
    `PATTERNS_VERSION` is bumped to 2 (BL-040).
  - Redaction now covers space-separated credential flags (`--password VALUE`) and
    URL or DSN embedded credentials (`scheme://user:SECRET@host`), and the stdio
    server redacts exception text before returning it to the client (BL-041).
  - The SSRF filter normalises obfuscated IPv4 forms (decimal, hex, octal,
    short-dotted, trailing-dot) so an encoded loopback is recognised, and
    `assert_egress_allowed` is fail-closed: a bare DNS name (which v0 does not
    resolve) is refused rather than allowed (BL-042; rebinding-aware resolution
    tracked as BL-046).
  - OpenTofu DRY_RUN runs a full `tofu plan` (not `plan -refresh-only`) so the
    preview scope matches the `apply` scope (BL-043).
  - `_bounded_error` contains a hostile or broken `__str__`, so `run()` always
    writes exactly one audit record and never raises out of the audited path
    (BL-044).
- Documentation honesty (BL-045): an ADR-0006 audit note records that the
  per-client consent registry was specified but never built; `SECURITY.md`,
  `LIMITATIONS.md`, and the STPA docs are qualified accordingly; the STPA SEC-7
  source path is corrected to `src/praxis/_ssrf.py`; and the read-tool audit claim
  is corrected (read tools read the store directly and are not individually
  audit-logged in v0, tracked as BL-062).

### Changed
- `ingest_observation` is annotated `read_only=false`: it writes (append-only)
  observed facts to the model, so the MCP annotation now reflects that. The
  generated `docs/schema/tools.schema.json` is regenerated accordingly.
