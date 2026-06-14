# Audit phase 1: validation baseline

Date: 2026-06-14
Environment: project venv driven by `uv run` (uv 0.11.14), dev tools from the
hash-locked `requirements-dev.txt` (`pip install --require-hashes`), CPython 3.12.
This baseline is the regression reference for subsequent change; it supersedes the
2026-06-12 baseline (ADR-0017), whose numbers are kept inline for comparison.

All numbers come from commands run in this session on a clean checkout
(merged tree `b2d17ce` = `209f61a` plus #69 and #71, working tree clean).

## Build from clean state

The editable install builds the `praxis` wheel metadata via hatchling without
errors. No compiled extensions. The container image builds from the repo
`Dockerfile` (not rebuilt this pass; ADR-0032).

## Test suite

Command: `uv run pytest -q` (config: `pythonpath=src`, `testpaths=tests`,
`--strict-markers`).

- Result: **372 passed, 23 skipped, 0 failed, 0 errors** (3.45 s).
  (2026-06-12: 226 passed, 1 skipped. The suite grew ~65 percent.)
- Skipped: the 23 skips are the live-PostgreSQL suite (`tests/store/
  test_postgres.py`), gated on `PRAXIS_TEST_PG_DSN`, which is unset here. This is
  the documented optional-backend skip (AGENTS.md "Optional backends skip cleanly
  when absent"); it includes the BL-103 concurrent-create-if-absent regression test.
- Flaky candidates: none observed; the suite is deterministic across the pytest and
  the coverage runs.

## Coverage (BL-053 gate)

Command: `uv run coverage run -m pytest -q && uv run coverage report`.

- Total: **92 percent** statement coverage (3111 statements, 254 missed).
  (2026-06-12: 94 percent, measured ad hoc.) Coverage is now a CI gate
  (`make coverage`, `fail_under` in `pyproject [tool.coverage.report]`, BL-053).
- Lowest file: `store/postgres.py` at 24 percent — its live-DB tests skip without
  `PRAXIS_TEST_PG_DSN`. Everything on the exercised (SQLite-default) path is at or
  above ~88 percent; the dip versus 2026-06-12 is the larger Postgres surface, not
  a regression on covered code.

## Lint, format, type-check, and the governance gates (check-only)

| Gate | Command | Outcome |
|---|---|---|
| Lint | `uv run ruff check .` | All checks passed |
| Format | `uv run ruff format --check .` | clean |
| Types | `uv run mypy` (strict, pydantic plugin) | Success: no issues found in 121 source files |
| Schema drift | `uv run python scripts/gen_schema.py --check` | schema up to date |
| Eval gate | `uv run python scripts/eval.py` | `P@1=1.000 MRR=1.000 (n=8)` PASS |
| Compliance | `uv run python scripts/validate_compliance.py` | catalog consistent with code, STPA constraints, and the compliance map |
| Helm | `helm unittest deploy/helm/praxis` | 34 tests, 4 suites, 1 chart, all pass |

`make ci-success` (lint, type-check, test, schema-check, eval, validate-compliance,
coverage) is green end to end, and the `helm-test` job equivalent passes.

## Security scanners (advisory, not gates)

| Check | Tool | Result |
|---|---|---|
| Dependency vulnerabilities | `pip-audit` | No known vulnerabilities found |
| SAST | `bandit -r src -ll` | 6 x B608 (Medium severity / Low confidence) on `store/sqlite.py` and `store/postgres.py`; all the `f"... WHERE {' AND '.join(clauses)}"` static-clause-join pattern with parameterized values — confirmed false positives (ruff `S608` is already scoped-ignored for these files in `pyproject.toml`). 0 High. |
| Fuzz | `scripts/fuzz.py 200000` | `200000 iterations (+ manifest/merkle/evidence stages), no violations` |

## CI reproduction notes

CI (`ci.yml`) runs `pip install --require-hashes -r requirements-dev.txt` then
`make ci-success` on Python 3.12/3.13/3.14. This session reproduced the gate set
via `uv run` and got the same green result. The 2026-06-12 drift notes (unpinned
dev tools, no lockfile, ci-matrix vs fuzz/sbom interpreter drift) are all closed:
the dev set is hash-locked (ADR-0033) and the ci matrix now covers 3.14 (#64).

## Baseline summary (regression reference)

- pytest: 372 passed / 23 skipped (live-Postgres) / 0 failed, ~3.5 s.
- ruff: 0 violations; format: clean. mypy strict: 0 errors, 121 files.
- schema drift: none. Eval: P@1 1.000, MRR 1.000, n=8, PASS. Compliance: consistent.
- helm unittest: 34 passed (4 suites). Coverage: 92 percent (gated).
- Dependency vulns: 0 (pip-audit). Fuzz: 200000 iterations, 0 violations.
- bandit: 6 false-positive B608, 0 High.
