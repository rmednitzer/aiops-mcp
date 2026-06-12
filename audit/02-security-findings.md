# Audit phase 2 and 3: findings register

Date: 2026-06-12
Scope: full read-only security audit (phase 2) and code-quality audit (phase 3).
Every finding cites a command run in this session or a `file:line` read in this
session. Unverifiable claims are marked `[UNVERIFIED]`.

## Method and tooling actually available

| Check | Tool | Availability | Result |
|---|---|---|---|
| Dependency vulnerabilities | `pip-audit` 2.10.1 | installed this session | No known vulnerabilities found (editable `praxis` skipped) |
| SAST | semgrep | not available | Manual OWASP Top 10 pass (below) |
| Secret scanning | gitleaks / trufflehog | not available | Manual regex sweep of tree and full git history |
| Type safety | mypy 2.1.0 strict | installed | 0 errors, 107 files |
| Lint (incl. `S`/bandit rules) | ruff 0.15.17 | installed | 0 violations |
| Fuzz | `scripts/fuzz.py` | in-repo | 200000 iterations, no violations |

The pip-audit invocation and its `No known vulnerabilities found` output are
recorded in the baseline session; the fuzz run printed
`fuzz: 200000 iterations, no violations`.

## Headline result

No Critical, High, or Medium severity findings. The four prior audit waves
(ADR-0011 through ADR-0016, backlog BL-017 through BL-090) closed the injection,
SSRF, approval-forgery, redaction, and append-only classes. This pass verifies
those controls are present in code and records a small set of Low and Info items,
most already tracked, plus one sharpened finding where a resolved backlog item was
fixed on only one of two store backends.

## Dependency and supply-chain audit

- Runtime dependency surface is one package (`pydantic>=2,<3`); optional extras add
  `psycopg[binary]` and the dev tools. `pip-audit` reports no known vulnerabilities
  against the resolved 2026-06-12 environment.
- GitHub Actions are pinned to full commit SHAs with version comments (verified by
  reading all five workflows). Top-level `permissions: contents: read`; codeql
  raises only `security-events: write` at job scope. `dependency-review` fails on
  high. These are good supply-chain hygiene.
- Gaps: dev tools and the SBOM/fuzz interpreter are unpinned and no lockfile is
  committed (Q-03, Q-04); no Dockerfile backs the referenced container image
  (Q-02). All Low/Info and tracked or newly filed.

## Manual OWASP-relevant pass (verified by reading the code this session)

| Category | Surface | Assessment | Evidence |
|---|---|---|---|
| Command injection | actuation adapters | argv is always a list, never a shell string; `subprocess.Popen` with no `shell=True`; ssh/ansible targets must match `SAFE_TARGET` (leading-alnum, no option injection); talosctl uses a verb allowlist and refuses post-verb `-` tokens; playbook/runbook paths confined to a configured root | `actuation/base.py:143-177`, `ssh.py:48-72`, `talosctl.py:128-161`, `base.py:101-122` |
| SSRF | server-initiated egress | fail-closed filter blocks loopback/link-local/RFC1918/CGNAT/ULA/reserved in dotted, integer, hex, octal, and trailing-dot encodings; a bare DNS name is refused (not resolved) | `_ssrf.py:25-104` |
| Path traversal | playbook/runbook/store paths | `confine_to_root` resolves symlinks and rejects any path escaping the configured root; fail-closed when unset | `actuation/base.py:101-122` |
| Authz / privilege | tier gate + approval | deny-first global list, mode ceiling, T2+ human gate; server-minted single-use TTL nonce bound to action/target/tier/patterns-version, surfaced out-of-band; T3 one-target-at-a-time | `execution/policy.py:72-123`, `execution/contract.py:173-289`, `execution/runner.py:334-413` |
| Deserialization | tool args, collectors, store JSON | pydantic strict models with `extra='forbid'` at the boundary; collectors are pure parsers; stored JSON loaded with a dict-or-empty guard | `tools/registry.py:23-126`, `collectors/base.py`, `store/sqlite.py:143-145` |
| SQL injection | both store backends | every value bound as a parameter; table names are literals; the `S608` ignore is scoped to the two store files and justified in pyproject | `store/sqlite.py`, `store/postgres.py`, `pyproject.toml:43-47` |
| Crypto misuse | approval nonce, audit chain | `secrets.token_urlsafe(16)` for nonces; SHA-256 hash chain with RFC 6962 domain separation; honest that `LocalStamper` is keyless (forgeable) and tracked | `execution/contract.py:214`, `audit/merkle.py`, `audit/evidence.py:11-18` |
| Unsafe defaults | transport, mode, redaction | stdio default; mode defaults guarded; HTTP fails closed without token + non-loopback opt-in; restricted output default-denied over HTTP; broad secret redaction before any audit write | `config.py:128-142`, `context.py:62-71`, `execution/redaction.py` |
| DoS / resource | stdio reader, ingest, args | per-line read bounded to 16 MiB; ingest body capped at 4 MiB at the boundary; `redact_args` depth-bounded to 32; RecursionError on nested JSON contained as a parse error | `server.py:37,133-161`, `tools/collect.py:34`, `execution/redaction.py:99-135` |

## Findings (register)

Schema: ID, title, severity, CWE, file:line, evidence, exploit-plausibility,
recommended fix, effort.

### Q-01 Postgres `seq` race not closed though BL-054/BL-068 are marked resolved (Low)

- Severity: Low. CWE-362 (race condition).
- file:line: `src/praxis/store/postgres.py:84-114` (schema has no `seq` unique
  index), `src/praxis/store/postgres.py:289-298` (`_next_seq` is a separate
  `SELECT COALESCE(MAX(seq), -1) + 1` statement from the INSERT).
- Evidence: the SQLite backend computes `seq` inside the INSERT and adds
  `facts_seq_unique` / `edges_seq_unique` partial-free unique indexes
  (`store/sqlite.py:53,107,196-200`), explicitly to turn a cross-instance
  `MAX(seq)+1` race into a loud `IntegrityError` (BL-068, resolved). The Postgres
  backend has neither: `_next_seq` reads the max in a statement separate from the
  INSERT, and no unique index exists on `facts.seq` or `edges.seq`. BL-054
  ("seq uniqueness or identity column to remove the `MAX(seq)+1` race") and BL-068
  are both marked `resolved`, but the fix landed on the SQLite path only.
- Exploit plausibility: low. The default deployment is single-process and
  single-operator (one `PostgresStore`, one connection). Two concurrent writers
  against the same database (a future multi-replica deployment, which the Helm
  chart's `replicaCount` makes reachable) could interleave the read and the insert
  and produce duplicate `seq` values, silently corrupting fact ordering rather than
  failing loudly. Not a confidentiality or actuation bypass.
- Recommended fix: add `CREATE UNIQUE INDEX IF NOT EXISTS facts_seq_unique ON
  facts (seq)` and the edges equivalent to `postgres.py::_SCHEMA`, bringing it to
  parity with SQLite. This is a schema change, so per the audit ground rules it is
  filed as a backlog proposal (BL-091), not executed in this pass. It also cannot
  be regression-tested in this environment (`psycopg` and a live Postgres are
  absent; `tests/store/test_postgres.py` skips).
- Effort: S.

### Q-02 No committed Dockerfile despite a referenced, digest-pinned container image (Info)

- Severity: Info. CWE-1104 (use of unmaintained/!reviewable third-party build).
- file:line: `deploy/helm/praxis/values.yaml:4` and `deploy/zarf.yaml:14`
  reference `ghcr.io/rmednitzer/praxis@sha256:...`; a repo-wide search finds no
  `Dockerfile`/`Containerfile`.
- Evidence: `find . -iname '*dockerfile*'` returns nothing; the image is named in
  two deploy manifests only.
- Exploit plausibility: not directly exploitable. The concern is supply-chain
  reviewability: the container the Helm/zarf artifacts deploy cannot be built or
  inspected from this repo, which is at odds with the digest-pinning supply-chain
  posture (ADR-0001). The default digest is an all-zero placeholder (already
  tracked as BL-033), so nothing pulls today.
- Recommended fix: add a minimal, non-root, pinned-base (ideally distroless)
  Dockerfile that builds `python -m praxis`, and wire an image-build/publish step,
  or document the external build location. Filed as BL-092 (adjacent to BL-033).
- Effort: S.

### Q-03 No dependency lockfile committed; dev tools float (Info, tracked BL-088)

- Severity: Info. CWE-1357 (reliance on unpinned components).
- file:line: `pyproject.toml:19-22` (`dev = ["ruff", "mypy", "pytest"]`,
  unpinned); no `uv.lock`/`requirements*.txt` tracked.
- Evidence: `ls uv.lock` fails on a clean checkout; `uv sync --extra dev`
  (the README quickstart command) generates an 87 KiB `uv.lock` that is untracked
  and not in `.gitignore`; mypy resolved to a new major (2.1.0) on 2026-06-12.
- Exploit plausibility: low (build reproducibility and a future surprise breakage,
  not a runtime vulnerability). Already tracked as BL-088 ("bound
  ruff/mypy/pytest/psycopg/hatchling versions, add a hash-locked dev requirements
  file for CI installs"). This pass adds the observation that the quickstart leaves
  an untracked `uv.lock`, so the lock-vs-ignore decision should be made explicitly.
- Recommended fix: per BL-088; decide whether to commit `uv.lock` or add it to
  `.gitignore`. No new backlog id.
- Effort: S.

### Q-04 CI test matrix (3.12/3.13) vs fuzz/sbom interpreter (3.14) drift (Info, adjacent BL-088)

- Severity: Info.
- file:line: `.github/workflows/ci.yml:19` (matrix `3.12`, `3.13`),
  `.github/workflows/fuzz.yml:18` and `sbom.yml` (`3.14`).
- Evidence: read of the four workflow files.
- Exploit plausibility: none. The fuzz harness exercises an interpreter the test
  matrix does not cover, so a 3.14-only behavior change in the security surfaces
  would surface in the nightly fuzz rather than the PR gate. BL-088 already calls
  for pinning the fuzz interpreter to a stable Python.
- Recommended fix: per BL-088; either add 3.14 to the ci matrix or pin fuzz/sbom to
  a matrix-covered version. No new backlog id.
- Effort: XS.

### Q-05 Helm chart default `transport: http` deploys a crash loop in v0 (Info)

- Severity: Info.
- file:line: `deploy/helm/praxis/values.yaml` (`transport: http`),
  `src/praxis/server.py:197-200` (any non-stdio transport raises
  `NotImplementedError`).
- Evidence: read of both files; `deploy/README.md:27-33` documents HTTP serving as
  "staged behind the enforced transport guard" and names stdio as the working path.
- Exploit plausibility: none (it fails closed, into CrashLoopBackOff, exposing
  nothing). The concern is operator-facing correctness: `helm install` with default
  values yields a pod that cannot start, while the chart presents HTTP as the
  deployment mode. The deploy README is honest about this, so it is Info, not a
  defect.
- Recommended fix: when HTTP serving lands (its own large item, BL-012/LIMITATIONS),
  this resolves itself; until then consider a values comment or a chart `NOTES.txt`
  warning. Folded into BL-093 (deploy doc clarity).
- Effort: XS.

## Items verified present (no finding)

These were checked and found correctly implemented; listed so the register is a
complete record, not only a defect list.

- Secrets: none in the working tree or in full git history. The only matches are the
  canonical AWS documentation example `AKIAIOSFODNN7EXAMPLE` and a fake PEM, both in
  redaction tests and the fuzzer (by design). No `.env`, key, or real-inventory file
  is tracked (`.gitignore` excludes `config/inventory.yaml`, `*.db`, `.env`).
- Append-only state enforced at the storage layer (SQLite triggers + partial unique
  index; Postgres PL/pgSQL trigger functions guarding every identity column),
  verified against invariant 4.
- The single audited path writes exactly one record per call including denials and
  errors; output bodies are never stored, only `output_sha256` + `output_len`; the
  logger degrades to stderr and never raises (invariant 1, 3).
- host_type gate refuses cross-type actuation as a HARD audited precondition before
  any argv is built (invariant 5).
- Trifecta containment is enforced inside the runner off a shared session taint
  latch; reads of observed facts arm it (invariant 8).
