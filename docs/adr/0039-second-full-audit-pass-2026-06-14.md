# ADR-0039: Second full audit, validation, and adversarial-testing pass (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (read-only audit pass following the ADR-0018..0038 remediation
and feature waves)

## Context

ADR-0017 recorded the first full, phased, read-only audit (2026-06-12, HEAD
`dc69596`). It found no Critical/High/Medium issues and filed one sharpened Low
finding plus four Info items: BL-091 (the Postgres `seq` race left unmitigated on
one of two backends), BL-092 (no reviewable Dockerfile behind the digest-pinned
image), BL-093 (the Helm `transport: http` default crash-loops in v0), and two
Info items folded into BL-088 (unpinned dev tools / missing lockfile; the
ci-matrix vs fuzz/sbom interpreter drift).

This ADR records a second pass run on 2026-06-14, after the ADR-0018..0038 waves.
The audit examined HEAD `209f61a`; during the governance write-back two PRs merged
to `main` — #69 (ADR-0037, the BL-100 multi-sink audit fan-out) and #71 (ADR-0038,
the BL-101 request/client audit correlation) — so this pass was rebased onto
`origin/main` (`b2d17ce` = `209f61a` plus #69 and #71), the full gate suite re-run
on the merged tree, and both deltas reviewed (see below). The numbers in `audit/01`
and the metrics table are the merged-tree results.

Like ADR-0011 and ADR-0017, this is not a remediation wave: its purpose is to
re-validate the current state with fresh, command-backed evidence, run an executed
adversarial battery against the live controls, confirm the disposition of every
prior finding, and file what (if anything) is new.

The phase evidence is refreshed in place under `audit/` (the living regression
reference per ADR-0017 Decision 1; git preserves the 2026-06-12 snapshot):

- `audit/00-inventory.md`: component map, dependency surface, toolchain, CI.
- `audit/01-baseline.md`: the 2026-06-14 regression baseline (372 passed / 23
  skipped; ruff, mypy strict, schema-drift, eval, compliance, coverage, and
  helm-unittest gates all green; 92 percent coverage).
- `audit/02-security-findings.md`: the findings register, the disposition of the
  2026-06-12 findings, and the executed adversarial probe results.
- `audit/03-final-report.md`: the executive summary and residual-risk statement.

What this pass verified with commands run in the session (merged tree `b2d17ce`):

- `make ci-success` is green end to end: ruff check + format (clean), mypy strict
  (0 issues, 121 files), pytest (372 passed, 23 skipped — the live-Postgres suite,
  gated on `PRAXIS_TEST_PG_DSN`), schema-drift (up to date), eval
  (P@1=1.000, MRR=1.000, n=8), validate-compliance (catalog consistent), and the
  coverage floor (92 percent, BL-053). `helm unittest deploy/helm/praxis` passes
  (34 tests, 4 suites, 1 chart).
- `pip-audit` against the hash-locked dev set: no known vulnerabilities.
- `scripts/fuzz.py 200000` (plus the manifest/merkle/evidence stages): no
  violations.
- An executed adversarial probe battery (`audit/02`): the SSRF filter blocks
  loopback/metadata/CGNAT/6to4 across decimal, hex, octal, IPv6-mapped, and
  trailing-dot encodings, refuses a bare name, and refuses a name that rebinds to a
  private address while pinning a public literal; redaction collapses five secret
  shapes plus key-name values and contains a 200-deep args bomb; the policy gate is
  deny-first in OPEN mode, floors privilege escalation at T2, and enforces the
  readonly/guarded ceilings; a forged, replayed, or wrong-target approval nonce is
  rejected; and the audit hash chain detects a tampered middle record at its exact
  index. 5/5 controls held.
- The two concurrently-merged deltas were reviewed and preserve the audit-integrity
  invariants: #69's `MultiSink`/`SyslogAuditSink` keeps the append-only
  hash-chained file write authoritative and first, fans out secondaries afterward
  with per-sink `Exception` containment (`emit` never raises, `BaseException`
  propagates), and forwards only the already-redacted line (SEC-9); #71's
  `request_id`/`client_id` are bounded (`bound_id`, 128 chars, never raising) and
  carried inside the hashed payload, so `verify_chain` stays consistent.
- `bandit -r src` reports only six B608 (Medium severity, Low confidence) on the
  two store backends; each is the `f"... WHERE {' AND '.join(clauses)}"` pattern
  where `clauses` are static literal fragments and every value is bound as a
  parameter — confirmed false positives. Ruff's equivalent `S608` is already scoped
  -ignored for the store files in `pyproject.toml`; bandit is not a CI gate.

Disposition of the 2026-06-12 (ADR-0017) findings — all closed before this pass:

| Finding | 2026-06-12 status | 2026-06-14 disposition |
|---|---|---|
| Q-01 / BL-091 (Postgres `seq` race) | Low, open | Resolved: `facts_seq_unique`/`edges_seq_unique` + inline `MAX(seq)+1` and the `FOR UPDATE` CAS in `store/postgres.py` (the 0018 wave); live-verified by BL-103 |
| Q-02 / BL-092 (no Dockerfile) | Info, open | Resolved: minimal non-root, digest-pinned-base `Dockerfile` (ADR-0032) |
| Q-03 / BL-088 (no lockfile, dev tools float) | Info, tracked | Resolved: `uv.lock` + hash-locked `requirements-dev.txt`, Renovate-maintained (ADR-0033) |
| Q-04 / BL-088 (ci 3.12/3.13 vs fuzz/sbom 3.14) | Info, tracked | Resolved: ci matrix now tests 3.12/3.13/3.14 (#64) |
| Q-05 / BL-093 (Helm `transport: http` crash loop) | Info, open | Resolved as documented: `values.yaml` v0 warning + `NOTES.txt` install-time warning |

The first pass's "top-5 residual risks" (BL-076 runtime anchoring, BL-095
non-forgeable RFC 3161 stamper, BL-046 rebinding-aware SSRF, BL-091, BL-012
transport guards) are all now `resolved`, as are the two items that were still open
at audit time: BL-100 (multi-sink audit fan-out, #69/ADR-0037) and BL-101
(request/client correlation, #71/ADR-0038), both closed during this write-back. The
backlog therefore stands at 103 of 103 prior items resolved; this pass adds BL-104,
which becomes the sole open item.

What this pass found: no Critical, High, Medium, or Low findings. One Info/latent,
forward-looking observation — filed as BL-104.

## Decision

1. Accept the refreshed evidence under `audit/` as the 2026-06-14 baseline and
   findings record. It supersedes ADR-0017's baseline as the regression reference;
   ADR-0017 and its 2026-06-12 numbers remain the historical record of that pass
   (preserved in git history).

2. File the one net-new observation as a backlog item, not as an in-pass code
   change:

   - BL-104 (Info, latent, CWE-362/CWE-668): the server builds a single
     `ExecutionContext` per process, so the session taint latch (`SessionTaint`)
     and the `ApprovalRegistry` are process-global, and `ApprovalRegistry`'s
     `validate`-then-`consume` is not atomic. On the stdio transport — single
     process, single-threaded request loop, one operator — this is correct and
     safe (the global latch fails safe by over-tainting; there is no concurrency).
     It would become load-bearing only if/when the multi-client HTTP transport
     (BL-012 serving, still `NotImplementedError`) multiplexes clients onto one
     context: per-session taint isolation and an atomic compare-and-consume on the
     nonce would then be required so one client cannot observe another's taint or
     race a single-use approval. #71's `client_id` correlation is adjacent
     groundwork (it labels records per client) but does not isolate the latch or
     the nonce, so BL-104 stands. Not reachable today; tracked for the transport
     work.

3. Make no code change in this pass. The one finding is latent on a transport that
   is not implemented (the server refuses any non-stdio bind, fail-closed), so
   there is nothing to harden yet, and the standing rules ("no behavior change
   without a test"; "fix the cause or hand back, never weaken a default to pass")
   make the disciplined outcome a tracked proposal, not speculative concurrency
   code against an absent code path. The #69 and #71 deltas were reviewed (they
   preserve the audit invariants), so the clean bill extends to the merged tree.

4. Refresh the `audit/` evidence files in place rather than fork a dated parallel
   set. ADR-0017 Decision 1 designated them the living regression reference;
   keeping one current set (with the prior-pass findings carried as an explicit
   disposition table) keeps the record readable, and git preserves the 2026-06-12
   text. This ADR is the forward record of the refresh.

## Consequences

Positive:

- The current state is re-validated with fresh, command-backed evidence, including
  an executed adversarial battery, not only a code re-read, and the validation was
  re-run on the merged tree so it covers the concurrently-landed #69 and #71 deltas.
- Every ADR-0017 finding is shown closed with its resolving ADR/backlog id, so the
  governance record now reflects that the first audit's debt is fully paid.
- The one forward-looking concurrency concern is captured (BL-104) before the HTTP
  transport work begins, rather than discovered during it.

Negative:

- A reader expecting new defects finds none; this pass ships evidence and one
  latent backlog item, not code. That is the intended result for a hardened,
  fully-remediated codebase.
- Refreshing `audit/` in place means the 2026-06-12 prose lives only in git
  history; the disposition table in `audit/02` mitigates this by carrying the prior
  findings forward.

Neutral:

- `coverage`, `pip-audit`, and `bandit` were used for the audit; coverage is
  already a project gate (BL-053), while pip-audit and bandit remain advisory and
  are not added as dependencies or gates.
- Coverage reads 92 percent here versus 94 percent on 2026-06-12; the dip is the
  larger `store/postgres.py` surface whose live-DB tests skip without
  `PRAXIS_TEST_PG_DSN`, not a loss of coverage on exercised code.

## Alternatives considered and rejected

- Implement BL-104 (per-session context isolation / atomic nonce consume) in this
  pass. Rejected: the multi-client transport it protects is unimplemented, so the
  change would add concurrency machinery and tests against a code path that cannot
  run, shipping speculative complexity against the project's own "no behavior
  change without a test, no untested security code" discipline.
- Fork a dated `audit/2026-06-14/` set and leave the 2026-06-12 files untouched.
  Rejected: it would split the living regression reference into divergent copies;
  the disposition table plus git history preserves the prior pass without the fork.
- Add `# nosec B608` annotations to silence bandit on the store backends. Rejected:
  bandit is not a CI gate and ruff's `S608` is already scoped-ignored with a
  justification in `pyproject.toml`; a second suppression mechanism for the same
  confirmed false positive is redundant surface, not hygiene.
- Scope the audit to HEAD `209f61a` and ignore the concurrently-merged #69/#71.
  Rejected: the PR rebases onto a tree that includes them, so the honest baseline
  is the merged tree; the gates were re-run there and both deltas reviewed, so the
  evidence matches what ships.

## Revisit triggers

- HTTP serving lands (BL-012 serving), which makes BL-104 active: per-session
  execution-context isolation and an atomic approval compare-and-consume become
  required (building on #71's per-request correlation scope).
- The next remediation wave implements BL-104, at which point a remediation ADR
  (the ADR-0016 pattern) supersedes the tracking here.
