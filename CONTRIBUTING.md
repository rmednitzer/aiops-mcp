# Contributing

## Development loop

1. Read the impacted module(s) and the ADR/STPA item they trace to.
2. Make the minimal change; reuse helpers.
3. Run `make check` (ruff + mypy strict + pytest). Run `make schema` and
   `make eval` when relevant.
4. Add or adjust tests. A change to an invariant implies a change to its test.
5. Update `CHANGELOG.md` and the affected `docs/`.

## Governance discipline

- Decisions are ADRs in `docs/adr/` (immutable; supersede, do not rewrite).
- Work items are `BL-NNN` in `docs/backlog.md` (stable ids; never deleted; each
  cites its source ADR).
- Safety and security requirements are derived in `docs/stpa/`. Every
  state-changing tool maps to at least one Unsafe Control Action; every security
  constraint maps to an enforcement mechanism.

## Style

- Python 3.12+, type hints required, ruff + mypy strict.
- No em dashes, no double hyphens as prose punctuation (backticked code flags are
  fine). SI units, ISO 8601 dates, 24h UTC.

## Branches and PRs

- Branch from `main` with a descriptive name. Imperative commit subjects that
  explain the why.
- PRs must pass `make check` and the CI aggregate before merge.

## Self-contained rule

No imports from, or runtime dependencies on, any other repository. If you need a
pattern from elsewhere, reimplement it natively and record the decision in an ADR.
