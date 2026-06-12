# Audit phase 1: validation baseline

Date: 2026-06-12
Environment: CPython 3.13.12 venv (`uv venv --python /usr/bin/python3.13 .venv`),
dependencies installed with `uv pip install -e ".[dev]"`.
Resolved versions: pydantic 2.13.4, pydantic-core 2.46.4, ruff 0.15.17,
mypy 2.1.0, pytest 9.0.3.

This baseline is the regression reference for every later change in this audit.
All numbers come from commands run in this session on a clean checkout
(HEAD `dc69596`, working tree clean).

## Build from clean state

| Step | Command | Outcome |
|---|---|---|
| venv | `uv venv --python /usr/bin/python3.13 .venv` | OK (CPython 3.13.12) |
| install | `uv pip install -e ".[dev]"` | OK, 15 packages, no resolution warnings |

The editable install builds the `praxis` wheel metadata via hatchling without
errors. No compiled extensions; nothing else to build.

## Test suite

Command: `pytest -q` (configuration from `[tool.pytest.ini_options]`:
`pythonpath=src`, `testpaths=tests`, `--strict-markers`).

- Result: 226 passed, 1 skipped, 0 failed, 0 errors.
- Runtime: 2.41 s to 2.97 s across three runs in this session (wall clock,
  single process).
- Skipped: `tests/store/test_postgres.py:9`, reason
  `could not import 'psycopg': No module named 'psycopg'`. This is the
  documented optional-backend skip (AGENTS.md "Optional backends skip cleanly
  when absent").
- Flaky candidates: none observed; three consecutive full runs produced
  identical results (226/1/0 each time).

## Coverage

The project has no coverage tooling configured (no `coverage`/`pytest-cov` in
dev extras, no `.coveragerc`, no CI coverage step). Measured ad hoc for this
audit with coverage 7.14.1 (`coverage run -m pytest -q`):

- Total: 94 percent statement coverage (`coverage report --format=total`).
- Lowest files: `store/postgres.py` 23 percent (its tests skip without
  psycopg), `store/__init__.py` 54 percent (backend selection branches),
  `schema.py` 65 percent, `server.py` 87 percent, `tools/_audited.py` 88
  percent. Everything else is at or above 89 percent.

## Lint, format, type-check (check-only)

| Gate | Command | Outcome |
|---|---|---|
| Lint | `ruff check .` | All checks passed |
| Format | `ruff format --check .` | 111 files already formatted |
| Types | `mypy` (strict, pydantic plugin) | Success: no issues found in 107 source files (4.7 s) |
| Schema drift | `python scripts/gen_schema.py --check` | `schema up to date`, exit 0 |
| Eval gate | `python scripts/eval.py` | `dispatch eval: P@1=1.000 MRR=1.000 (n=8)` PASS |

`make ci-success` is therefore green end to end (the Makefile aggregates
exactly these five gates).

## CI reproduction and drift notes

CI (`.github/workflows/ci.yml`) runs `pip install -e ".[dev]"` then
`make ci-success` on Python 3.12 and 3.13. This session reproduced the 3.13
lane (3.13.12 vs whatever patch the runner has) and got the same green result.
Observed drift between CI config and local reality:

1. Dev tools are unpinned and no lockfile exists, so CI tool versions float
   with PyPI. On 2026-06-12 that resolves to mypy 2.1.0 (a new major series)
   and ruff 0.15.17, both green against this codebase, but the gate is not
   reproducible over time by construction.
2. `sbom.yml` and `fuzz.yml` run Python 3.14 while `ci.yml` tests only 3.12
   and 3.13; the fuzz harness therefore exercises an interpreter the test
   matrix does not cover.
3. The default `python` on this audit machine is 3.11.15, below
   `requires-python >=3.12`; the README quickstart works only because `uv`
   selects a newer interpreter. Worth one README sentence (phase 5).
4. `README.md` quickstart says `uv sync --extra dev`, but no `uv.lock` is
   committed, so `uv sync` generates a fresh lock on first run (it succeeds,
   but the "locked" workflow the command implies does not exist in the repo).

## Baseline summary (regression reference)

- pytest: 226 passed / 1 skipped / 0 failed, about 2.7 s.
- ruff: 0 violations; format: 0 diffs (111 files).
- mypy strict: 0 errors in 107 files.
- schema drift: none. Eval gate: P@1 1.000, MRR 1.000, n=8, PASS.
- Coverage (ad hoc): 94 percent total.
