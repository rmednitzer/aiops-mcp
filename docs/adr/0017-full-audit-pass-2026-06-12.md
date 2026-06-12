# ADR-0017: Full audit, validation, and hardening pass (2026-06-12)

## Status

Accepted

## Date

2026-06-12

## Authors

praxis maintainers (read-only audit pass following the ADR-0016 enforcement wave)

## Context

ADR-0011 through ADR-0016 were four audit and remediation waves that took the
codebase from scaffold to a state where `make ci-success` is green and each of the
nine invariants has a proving test, with the P1 self-approval and free-form-shell
findings closed (ADR-0016). This ADR records a fifth pass: a full, phased,
read-only audit (recon, validation baseline, security audit, code-quality audit)
followed by governance write-back, run on 2026-06-12 against HEAD `dc69596`.

Unlike ADR-0012/0013/0016, this pass is not a remediation wave. Its purpose was to
validate the current state with fresh evidence, look for regressions and
unverified governance claims, and file what it found. It follows the ADR-0011
precedent: a post-hoc audit recorded and accepted, with the resulting code work
tracked as backlog, not implemented in the same change.

The phase evidence lives under `audit/`:

- `audit/00-inventory.md`: component map, dependency graph, toolchain versions.
- `audit/01-baseline.md`: the regression baseline (226 passed, 1 skipped; ruff,
  mypy strict, schema-drift, and eval gates all green; 94 percent ad-hoc
  coverage).
- `audit/02-security-findings.md`: the findings register (phases 2 and 3).
- `audit/03-final-report.md`: the executive summary and residual-risk statement.

What the pass verified with commands run in the session:

- `pip-audit` 2.10.1 reports no known vulnerabilities in the resolved dependency
  set; the runtime surface is one package (`pydantic`).
- No secrets in the working tree or in full git history (the only matches are the
  canonical AWS documentation example key and a fake PEM, both in redaction tests
  and the fuzzer).
- The security spine holds on re-read: list-argv subprocesses (no shell), the
  fail-closed SSRF filter across IP encodings, path confinement with symlink
  resolution, the deny-first tier gate, the server-minted single-use TTL approval
  nonce, storage-layer append-only, in-path trifecta containment, and broad
  pre-audit redaction.
- `scripts/fuzz.py 200000` passes with no violations.
- The README quickstart executes: `uv sync --extra dev` succeeds and
  `python -m praxis` serves the stdio JSON-RPC handshake and writes the
  session-header audit record.

What the pass found (full detail in `audit/02-security-findings.md`): no Critical,
High, or Medium findings. One sharpened Low finding and four Info items, most
already tracked.

## Decision

1. Accept the audit evidence under `audit/` as the 2026-06-12 baseline and
   findings record. The baseline in `audit/01-baseline.md` is the regression
   reference for subsequent change.

2. File the net-new findings as backlog items, not as in-pass code changes:

   - BL-091 (Low, CWE-362): the Postgres backend still computes `seq` as a
     separate `SELECT MAX(seq)+1` with no unique index, so the race BL-054/BL-068
     closed on the SQLite path is unmitigated on the Postgres path. ADR-0016
     Decision 6 scoped that fix to "The SQLite store file ... seq is computed
     inside the INSERT under a unique index"; this records that the Postgres
     equivalent was not delivered.
   - BL-092 (Info): no reviewable Dockerfile backs the digest-pinned container
     image the Helm and zarf artifacts reference.
   - BL-093 (Info): the Helm chart default `transport: http` crash-loops in v0,
     where only stdio serves; document it at install time until HTTP serving lands.

   The remaining Info items (unpinned dev tools and the missing lockfile; the
   ci 3.12/3.13 vs fuzz/sbom 3.14 interpreter drift) are already covered by BL-088
   and are not re-filed.

3. Make no code change in this pass. The only finding with a concrete code fix
   (BL-091) is a Postgres schema change, which the audit ground rules route to the
   backlog as a proposal, and which cannot be regression-tested in an environment
   without `psycopg` or a live Postgres (`tests/store/test_postgres.py` skips). The
   standing rule "never weaken a default to make something pass; fix the cause or
   hand back" and "no behavior change without a test" mean the disciplined outcome
   is to record and defer, not to ship an untested store-write change.

4. Adapt the generic audit-prompt deliverable templates to this repo's established,
   stricter governance rather than fork parallel artifacts. The prompt proposed a
   `docs/adr/` MADR scheme and a root `BACKLOG.md`; this repo already runs
   `docs/adr/NNNN-*.md` (this format) and `docs/backlog.md` with stable, never
   renumbered `BL-NNN` ids. Per CLAUDE.md, findings extend `docs/backlog.md`
   (BL-091..BL-093) and this ADR is the forward record; no parallel backlog or ADR
   tree is created. The `audit/` evidence reports are net-new and do not conflict.

## Consequences

Positive:

- The current state is re-validated with fresh, command-backed evidence, and the
  baseline is captured for future regression comparison.
- A governance-traceability gap is closed in the record: BL-068's resolution is
  now correctly scoped to SQLite, and the Postgres residual is tracked as BL-091
  rather than implied closed.
- Supply-chain and deploy-doc gaps (BL-092, BL-093) are visible in the backlog.

Negative:

- The Postgres `seq` race remains live until BL-091 is implemented and tested
  against a real Postgres; the residual risk is recorded in the final report.
- A reader who expected a remediation wave finds none: this pass deliberately
  ships evidence and backlog, not code.

Neutral:

- `coverage` and `pip-audit` were installed for the audit only; they are not
  added to the project dependencies (coverage tooling as a gate is BL-053).
- The audit used a Python 3.13 virtualenv because the environment's default
  interpreter is 3.11, below `requires-python >=3.12`; `uv` selected a compliant
  interpreter for every gate.

## Alternatives considered and rejected

- Implement BL-091 (the Postgres `seq` unique index) in this pass for
  completeness. Rejected: it is a schema change to a backend with no test coverage
  reachable here, so it would ship untested against the audit's own rules; the
  honest move is a tracked proposal.
- Create the root `BACKLOG.md` and `docs/adr/` MADR files the audit prompt
  described. Rejected: it would fork the repo's stable-id backlog and immutable-ADR
  governance, which CLAUDE.md makes load-bearing; the existing scheme is extended
  instead.
- Strip the verbose invariant-rationale comments under a "delete comments that
  restate the obvious" reading of the docs phase. Rejected: in this codebase the
  comments encode the why behind security invariants (the explicit house style)
  and were verified accurate; removing them would lose governance context, not
  noise.

## Revisit triggers

- A multi-replica or HTTP deployment makes concurrent Postgres writers real,
  raising BL-091 from latent to active.
- HTTP serving lands (BL-012), which resolves BL-093 and changes the deploy
  default's meaning.
- The next audit wave implements any of BL-091..BL-093 or the open structural
  items, at which point a remediation ADR (the ADR-0016 pattern) supersedes the
  tracking here for those items.
