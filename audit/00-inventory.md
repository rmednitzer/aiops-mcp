# Audit phase 0: recon and inventory

Date: 2026-06-12
Auditor: automated full-pass audit (read-only phase)
Branch under audit: `claude/youthful-turing-3b12uf` (clean tree at start, HEAD `dc69596`)

Every statement below is backed by a command run in this session on 2026-06-12.
Commands are quoted where the result is non-obvious.

## Component map

| Component | Location | Purpose |
|---|---|---|
| Execution core | `src/praxis/execution/` | Single audited execution path: `patterns.py` (tier classification), `policy.py` (mode/deny/tier gates), `redaction.py`, `audit.py` (hash-chained audit log), `contract.py` (pydantic input models), `runner.py` (fused `run` entry point) |
| Fact model | `src/praxis/model/facts.py` | Bitemporal fact dataclasses |
| Store | `src/praxis/store/` | `base.py` (StoreProtocol), `sqlite.py` (default), `postgres.py` (optional, needs `psycopg`) |
| Collectors | `src/praxis/collectors/` | Read-only telemetry to facts: `osquery.py`, `aide.py`, `talos.py`, `probe.py`, `base.py` |
| Drift engine | `src/praxis/drift/` | `engine.py`, `findings.py`, `sources.py`, `converge.py` (human-gated convergence) |
| Actuation adapters | `src/praxis/actuation/` | `base.py`, `ssh.py`, `ansible.py`, `opentofu.py`, `runbook.py`, `talosctl.py`, `credentials.py` |
| Tamper-evident audit | `src/praxis/audit/` | `evidence.py`, `merkle.py` (RFC 6962), `rfc3161.py`, `session.py` |
| Skills engine | `src/praxis/skills/` | `manifest.py`, `registry.py`, `dispatch.py`, `eval.py` |
| MCP tool surface | `src/praxis/tools/` | `registry.py`, `_audited.py`, `actuate.py`, `collect.py`, `drift.py`, `emergency.py`, `state.py` |
| Server and entry | `src/praxis/server.py`, `__main__.py` | stdio JSON-RPC 2.0 server; refuses unsafe HTTP binds |
| Cross-cutting | `config.py`, `context.py`, `clock.py`, `schema.py`, `_ssrf.py` | env config, session context, clock, JSON-schema generation, SSRF egress filter |
| Skill bundles (data) | `skills/*/SKILL.md` | 5 bundles: audit-verification, drift-triage, fleet-inventory, ssh-hardening, talos-operations |
| Eval fixtures | `evaluation/` | `skills_golden.json` (dispatch gate), `drift/known_good.json`, `drift/observed.json` |
| Scripts | `scripts/` | `gen_schema.py`, `eval.py`, `fuzz.py`, `verify_audit.py` |
| Deploy | `deploy/` | Helm chart (`deploy/helm/praxis/`), systemd unit plus hardening drop-in, `zarf.yaml` |
| Governance | `docs/` | 16 ADRs plus index, STPA 01-07, `backlog.md`, `architecture.md`, `governance/compliance-map.md`, runbooks, committed JSON schemas |

Size (verified with `find ... | xargs wc -l`): 5969 lines in `src/`, 9597 lines
of Python total including tests. 45 test files.

## Languages, frameworks, build system

- Language: Python, `requires-python = ">=3.12"` (pyproject.toml). Pure Python,
  src layout, package `praxis`, `py.typed` marker present.
- Build backend: hatchling (`[build-system]` in pyproject.toml).
- Console entry points: `praxis = "praxis.__main__:main"` and `python -m praxis`.
- No web framework; the server is a hand-rolled stdio JSON-RPC 2.0 loop
  (`src/praxis/server.py`). HTTP transport intentionally not implemented (README,
  LIMITATIONS.md).
- Lint/format: ruff (`E,F,I,W,UP,B,S` rule families, line length 100). Types:
  mypy strict with the pydantic plugin. Tests: pytest with `--strict-markers`.

## Dependencies

Direct runtime dependencies: 1 (`pydantic>=2,<3`).
Optional extras: `postgres` (`psycopg[binary]`), `dev` (`ruff`, `mypy`, `pytest`,
all unpinned).

Lockfile state: none. No `uv.lock`, `requirements*.txt`, or other pin set is
committed (`ls uv.lock` fails), although `README.md` quickstart instructs
`uv sync --extra dev`, which expects to create or use one. Dev tool versions in
CI therefore float (see baseline report for resolved versions on 2026-06-12).

Renovate is configured (`renovate.json`, `config:recommended`) and active
(history shows renovate commits for GitHub Actions and the SBOM Python version).

## CI configuration (`.github/workflows/`)

| Workflow | Trigger | Notes |
|---|---|---|
| `ci.yml` | push/PR to main | Python 3.12 + 3.13 matrix, `pip install -e ".[dev]"`, `make ci-success` (lint, type-check, test, schema drift guard, eval gate). Aggregate `ci-success` job for branch protection. |
| `codeql.yml` | push/PR, weekly cron | CodeQL `security-extended`, Python |
| `dependency-review.yml` | PR | `fail-on-severity: high` |
| `sbom.yml` | push to main, weekly cron | CycloneDX via `cyclonedx-bom==7.3.0` (pinned), Python 3.14 |
| `fuzz.yml` | nightly cron, manual | `scripts/fuzz.py 200000` over classification, policy, redaction surfaces, Python 3.14 |

All workflows declare top-level `permissions: contents: read`; codeql adds
`security-events: write` at job level. Every third-party action is pinned to a
full commit SHA with a version comment.

## Toolchain actually available in this environment

Verified by running the tools on 2026-06-12:

- System `python` / `python3`: 3.11.15 (below `requires-python`); `/usr/bin/python3.12`
  (3.12.3) and `/usr/bin/python3.13` (3.13.12) present; uv 0.8.17.
- Audit venv (created this session): CPython 3.13.12 via
  `uv venv --python /usr/bin/python3.13 .venv` then `uv pip install -e ".[dev]"`.
- Resolved tool versions in the venv: ruff 0.15.17, mypy 2.1.0, pytest 9.0.3,
  pydantic 2.13.4 (pydantic-core 2.46.4), hatchling via build isolation.
  coverage 7.14.1 and pip-audit 2.10.1 were installed from PyPI for the audit
  only (used in the baseline and security phases); neither is a project
  dependency.
- Not available and not used this pass: semgrep, gitleaks, trufflehog (no
  install was attempted; the security phase substitutes a manual SAST pass and a
  regex secret sweep). docker is present but has no running daemon.

## Git state

- 53 commits total, first commit 2026-06-07, HEAD `dc69596` (2026-06-10).
- Single long-lived branch `main`; work branch for this audit is
  `claude/youthful-turing-3b12uf` (session-designated; the task asked for
  `audit/2026-06-12-full-pass`, recorded here as a deliberate deviation because
  the execution environment mandates the designated branch).
- Working tree clean at audit start; no submodules; no vendored binaries.

## Entry points and external input surfaces (enumerated, assessed in phase 2)

1. stdio JSON-RPC requests (`server.py` loop) including MCP `tools/call` params.
2. Environment variables, `PRAXIS_`-prefixed, bound once at import
   (`src/praxis/config.py`).
3. Collector payloads (osquery/AIDE/talos JSON) via `ingest_observation`.
4. Skill bundle files (`skills/*/SKILL.md`) parsed by `skills/manifest.py`.
5. Drift desired/observed JSON documents (`evaluation/drift/*.json`, operator
   supplied at runtime).
6. Command output returned by actuation subprocesses (treated as untrusted).
7. Optional Postgres DSN and SQLite path (operator configuration).

No network listeners exist in v0 (stdio only; unsafe HTTP bind refused).
