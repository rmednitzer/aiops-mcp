# Audit phase 0: recon and inventory

Date: 2026-06-14
Auditor: automated full-pass audit (second pass; read-only recon phase)
Branch under audit: HEAD `209f61a`, rebased onto `origin/main` (`b2d17ce`, which adds #69/ADR-0037 and #71/ADR-0038); clean tree at start
Prior pass: 2026-06-12, HEAD `dc69596` (ADR-0017). This pass refreshes the
2026-06-12 inventory; the differences since then are called out inline.

Every statement below is backed by a command run in this session on 2026-06-14.

## Component map

| Component | Location | Purpose |
|---|---|---|
| Execution core | `src/praxis/execution/` | Single audited execution path: `patterns.py` (tier classification, `PATTERNS_VERSION=3`), `policy.py` (mode/deny/tier gates), `redaction.py`, `audit.py` (hash-chained audit log), `contract.py` (predicates, budget, minted approvals), `runner.py` (fused `run` entry point) |
| Fact model | `src/praxis/model/facts.py` | Bitemporal fact/edge dataclasses, `content_hash` for CAS |
| Store | `src/praxis/store/` | `base.py` (StoreProtocol, `VersionConflict`), `sqlite.py` (default), `postgres.py` (optional, needs `psycopg`) |
| Collectors | `src/praxis/collectors/` | Read-only telemetry to facts: `osquery.py`, `aide.py`, `talos.py`, `probe.py`, `base.py` |
| Drift engine | `src/praxis/drift/` | `engine.py`, `findings.py`, `sources.py`, `converge.py`, `cis.py` (human-gated convergence) |
| Actuation adapters | `src/praxis/actuation/` | `base.py`, `ssh.py`, `ansible.py`, `opentofu.py`, `runbook.py`, `talosctl.py`, `credentials.py` |
| Tamper-evident audit | `src/praxis/audit/` | `evidence.py`, `merkle.py` (RFC 6962), `rfc3161.py` (RFC 3161 TSA), `session.py` |
| Skills engine | `src/praxis/skills/` | `manifest.py`, `registry.py`, `dispatch.py`, `eval.py` |
| MCP tool surface | `src/praxis/tools/` | `registry.py`, `_audited.py`, `actuate.py`, `collect.py`, `drift.py`, `emergency.py`, `state.py` |
| Server and entry | `src/praxis/server.py`, `__main__.py` | stdio JSON-RPC 2.0 server; refuses unsafe HTTP binds (fail-closed) |
| Cross-cutting | `config.py`, `context.py`, `clock.py`, `schema.py`, `_ssrf.py` | env config, session context + trifecta latch, clock, JSON-schema generation, SSRF egress filter |
| Skill bundles (data) | `skills/*/SKILL.md` | 5 bundles: audit-verification, drift-triage, fleet-inventory, ssh-hardening, talos-operations |
| Eval fixtures | `evaluation/` | `skills_golden.json` (dispatch gate), `drift/known_good.json`, `drift/observed.json` |
| Scripts | `scripts/` | `gen_schema.py`, `eval.py`, `fuzz.py`, `verify_audit.py`, `validate_compliance.py` |
| Deploy | `deploy/` | Helm chart (`deploy/helm/praxis/`), systemd unit + hardening drop-ins, `zarf.yaml`, `RELEASE-CHECKLIST.md`, `Dockerfile` (repo root) |
| Governance | `docs/` | 39 ADRs plus index, STPA 01-07, `backlog.md` (104 items), `architecture.md`, `governance/`, runbooks, committed JSON schemas |

Size (verified with `find ... | xargs wc -l`): 7809 lines in `src/`, 13354 lines
of Python total including tests. 46 test files. (2026-06-12: 5969 `src/`, 45 test
files, 16 ADRs — the suite and governance set have grown.)

## Languages, frameworks, build system

- Language: Python, `requires-python = ">=3.12"` (pyproject.toml). Pure Python,
  src layout, package `praxis`, `py.typed` marker present.
- Build backend: hatchling. Console entry points: `praxis` and `python -m praxis`.
- No web framework; the server is a hand-rolled stdio JSON-RPC 2.0 loop
  (`src/praxis/server.py`). HTTP serving is staged, not implemented (fails closed);
  the transport guard/config surface is done (BL-012, README, LIMITATIONS.md).
- Lint/format: ruff (`E,F,I,W,UP,B,S` rule families, line length 100; `S608`
  scoped-ignored on the two store files). Types: mypy strict with the pydantic
  plugin. Tests: pytest with `--strict-markers`.

## Dependencies and supply chain

- Direct runtime dependencies: 1 (`pydantic>=2,<3`). Optional extras: `postgres`
  (`psycopg[binary]`), `tsa` (`cryptography>=49,<50`, for the RFC 3161 stamper),
  `dev`.
- Lockfile: `uv.lock` and a hash-locked `requirements-dev.txt` are committed and
  Renovate-maintained via the pip-compile manager (ADR-0033). (2026-06-12: no
  lockfile existed; closed since.)
- Container: a minimal, non-root, multi-stage `Dockerfile` builds `python -m
  praxis` on a digest-pinned `python:3.12-slim-bookworm` base (ADR-0032). The
  image `ghcr.io/rmednitzer/praxis` is digest-pinned in `deploy/helm/praxis/
  values.yaml` and `deploy/zarf.yaml`; both carry an all-zero placeholder digest
  that the operator replaces at first release (RELEASE-CHECKLIST.md, fail-closed).
  (2026-06-12: no Dockerfile existed; closed since.)
- `pip-audit` against the resolved dev set reports no known vulnerabilities.

## CI configuration (`.github/workflows/`)

| Workflow | Trigger | Notes |
|---|---|---|
| `ci.yml` | push/PR to main | Python 3.12/3.13/3.14 matrix, `pip install --require-hashes -r requirements-dev.txt`, `make ci-success`. The `ci-success` aggregate is the single required check; it invokes `codeql` and `dependency-review` as reusable-workflow jobs (BL-052, ADR-0036) and gates on their results with a skip-tolerant `if: always()` check. `helm-test` and `deps-consistency` jobs run alongside. |
| `codeql.yml` | weekly cron + `workflow_call` | CodeQL `security-extended`, Python; driven by `ci.yml` for PR/push, standalone for the weekly full scan (ADR-0036). |
| `dependency-review.yml` | `workflow_call` | `fail-on-severity: high`; invoked by `ci.yml` on PRs (skipped on push, tolerated by the aggregate). |
| `sbom.yml` | push to main, weekly cron | CycloneDX, pinned generator. |
| `fuzz.yml` | nightly cron, manual | `scripts/fuzz.py` over classification, policy, redaction, manifest/merkle/evidence. |
| `release.yml` | tag push | Tag-triggered publish with signed provenance + SBOM attestation (BL-033, ADR-0035). |

All workflows declare top-level `permissions: contents: read`; jobs raise only the
scopes they need. Every third-party action is pinned to a full commit SHA with a
version comment. (2026-06-12: ci-success was described as "required via branch
protection" with the security workflows external; ADR-0036 moved enforcement into
the CI graph.)

## Toolchain actually available in this environment

Verified by running the tools on 2026-06-14 (CPython 3.12.3 host, uv 0.11.14):

- Gates run via `uv run` against the project venv; resolved dev tools from the
  hash-locked set. helm 3.x with the `unittest` plugin (CI pins v1.1.1).
- `pip-audit` and `bandit` were run via `uv run --with` for the audit only;
  neither is a project dependency. coverage is a project gate (BL-053).
- Not used this pass: semgrep, gitleaks, trufflehog (the security phase uses an
  executed adversarial probe, a manual SAST re-read, bandit, and a secret sweep).

## Git state

- HEAD `209f61a`, rebased onto `origin/main` `b2d17ce` (adds #69/ADR-0037 and #71/ADR-0038), 2026-06-14. Working tree clean at audit start; no
  submodules; no vendored binaries.
- The audit work branch is session-designated per the execution environment.

## Entry points and external input surfaces (enumerated, assessed in phase 2)

1. stdio JSON-RPC requests (`server.py` loop) including MCP `tools/call` params
   (per-message bounded to 16 MiB; notifications not dispatched; batch refused).
2. Environment variables, `PRAXIS_`-prefixed, bound once at import (`config.py`).
3. Collector payloads (osquery/AIDE/talos JSON) via `ingest_observation` (4 MiB cap).
4. Skill bundle files (`skills/*/SKILL.md`) parsed by `skills/manifest.py`.
5. Drift desired/observed JSON documents (operator supplied at runtime).
6. Command output returned by actuation subprocesses (treated as untrusted; arms
   the session taint latch on read of observed facts).
7. Optional Postgres DSN and SQLite path (operator configuration).
8. Optional RFC 3161 TSA URL for evidence stamping (egress via the SSRF filter).

No network listeners exist in v0 (stdio only; unsafe HTTP bind refused).
