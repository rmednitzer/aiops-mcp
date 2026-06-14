# Audit phase 2 and 3: findings register

Date: 2026-06-14
Scope: full read-only security audit (phase 2), executed adversarial battery, and
code-quality audit (phase 3). Every finding cites a command run in this session or
a `file:line` read in this session.

This register supersedes the 2026-06-12 register (ADR-0017); the disposition of
that pass's findings is carried forward below so the record stays complete.

## Method and tooling actually available

| Check | Tool | Availability | Result |
|---|---|---|---|
| Dependency vulnerabilities | `pip-audit` | run this session | No known vulnerabilities found |
| SAST (rule-based) | `bandit -r src -ll` | run this session | 6 x B608, all false positives (below); 0 High |
| SAST (manual) | OWASP-relevant code re-read | this session | No new finding (table below) |
| Adversarial battery | in-session probe (`/tmp/audit/probe.py`) | run this session | 5/5 controls held |
| Type safety | `uv run mypy` strict | run this session | 0 errors, 121 files |
| Lint (incl. ruff `S`/bandit-equivalent) | `uv run ruff check .` | run this session | 0 violations |
| Fuzz | `scripts/fuzz.py 200000` | in-repo | 200000 iterations + manifest/merkle/evidence stages, no violations |
| Secret scan | manual regex sweep of tree | this session | only the canonical AWS doc-example key and a fake PEM, in redaction tests/fuzzer (by design) |

## Headline result

No Critical, High, Medium, or Low findings. The codebase is the product of six
audit/remediation waves (ADR-0011..0018) and the 0019..0036 feature/hardening
waves; this pass re-verifies the controls are present and, for the first time,
executes an adversarial battery against them (all held). One Info/latent,
forward-looking observation is filed as BL-104. The backlog stands at 103/103
prior items resolved (BL-100 by #69 and BL-101 by #71, both during this
write-back); this pass adds BL-104 (latent), the sole open item.

## Disposition of the 2026-06-12 (ADR-0017) findings — all closed

| ID | Title | 2026-06-14 disposition | Evidence |
|---|---|---|---|
| Q-01 / BL-091 | Postgres `seq` race unmitigated on one backend | **Resolved** | `store/postgres.py` `_SCHEMA` now has `facts_seq_unique`/`edges_seq_unique`; `_FACTS_INSERT`/`_EDGES_INSERT` compute `seq` inline; `put_fact_if` row-locks with `FOR UPDATE` and translates `IntegrityError`→`VersionConflict`. Backlog `resolved` (0018 wave); live-verified by BL-103. |
| Q-02 / BL-092 | No reviewable Dockerfile behind the pinned image | **Resolved** | `Dockerfile` present: multi-stage, non-root (uid 10001), digest-pinned base, `python -m praxis` over stdio (ADR-0032). |
| Q-03 / BL-088 | No lockfile; dev tools float | **Resolved** | `uv.lock` + hash-locked `requirements-dev.txt`, Renovate pip-compile manager (ADR-0033); CI installs `--require-hashes`. |
| Q-04 / BL-088 | ci 3.12/3.13 vs fuzz/sbom 3.14 drift | **Resolved** | `ci.yml` matrix now 3.12/3.13/3.14 (#64). |
| Q-05 / BL-093 | Helm `transport: http` crash-loops in v0 | **Resolved (documented)** | `values.yaml` carries a v0 warning block; `NOTES.txt` repeats it at install time. |

## Manual OWASP-relevant pass (verified by reading the code this session)

| Category | Surface | Assessment | Evidence |
|---|---|---|---|
| Command injection | actuation adapters | argv is always a list, never a shell string; `subprocess.Popen` with no `shell=True`, `stdin=DEVNULL`, `start_new_session`; targets must match `SAFE_TARGET` (leading-alnum, no option injection); env is allowlist-scrubbed so unrelated secrets never reach wrapped tools | `actuation/base.py` (`SAFE_TARGET`, `scrubbed_env`, `run_subprocess`) |
| SSRF | server-initiated egress | fail-closed filter blocks loopback/link-local/RFC1918/CGNAT/ULA/reserved/6to4-relay across dotted, integer, hex, octal, trailing-dot, and IPv6-mapped encodings; a bare name is refused; the resolving variant checks every resolved IP and pins the connection (rebinding-aware, BL-046) | `_ssrf.py` |
| Path traversal | playbook/runbook/store paths | `confine_to_root` resolves symlinks and rejects any escape; fail-closed when the root is unset | `actuation/base.py::confine_to_root` |
| Authz / privilege | tier gate + approval | deny-first global list (unconditional, all modes), mode ceiling, T2+ human gate; server-minted single-use TTL nonce bound to action/target/tier/patterns-version, surfaced out-of-band; T3 one-target-at-a-time; trifecta latch gates T1+ once untrusted content is ingested | `execution/policy.py`, `execution/contract.py`, `execution/runner.py`, `context.py` |
| Deserialization | tool args, collectors, store JSON | pydantic models at the boundary; collectors are pure parsers; stored JSON loaded with a dict-or-empty guard; non-finite embedding vectors skipped (BL-054) | `tools/registry.py`, `store/sqlite.py` |
| SQL injection | both store backends | every value bound as a parameter; only static literal clause fragments are interpolated; table names are literals; the `S608` ignore is scoped to the two store files and justified in `pyproject.toml` | `store/sqlite.py`, `store/postgres.py` |
| Crypto / tamper-evidence | approval nonce, audit chain, stamper | `secrets.token_urlsafe(16)` nonces; SHA-256 per-entry hash chain (genesis-anchored, seq-continuity checked); RFC 6962 Merkle evidence; a real RFC 3161 stamper (`tsa` extra) replaces the keyless `LocalStamper`, selected fail-closed (BL-095, ADR-0029) | `execution/contract.py`, `execution/audit.py`, `audit/merkle.py`, `audit/rfc3161.py` |
| Unsafe defaults | transport, mode, redaction, k8s | stdio default; mode `guarded`; HTTP fails closed without token + non-loopback opt-in; restricted output default-denied over HTTP; PSA-restricted pod (non-root, drop ALL, `readOnlyRootFilesystem`, seccomp `RuntimeDefault`, no token automount); default-deny NetworkPolicy; broad pre-audit redaction | `config.py`, `context.py`, `deploy/helm/praxis/templates/deployment.yaml`, `redaction.py` |
| DoS / resource | stdio reader, ingest, args, budget | per-line read bounded to 16 MiB; ingest body capped at 4 MiB; `redact_args` depth-bounded to 32; RecursionError on nested JSON contained as a parse error; optional per-session action/wall budget (BL-074) | `server.py`, `tools/collect.py`, `execution/redaction.py`, `execution/contract.py` |

## Executed adversarial battery (commands run this session)

`/tmp/audit/probe.py`, run via `uv run python`, exercises the live controls with
attack inputs and asserts each rejects them. Result: **5/5 controls held**.

| Probe | Attacks exercised | Outcome |
|---|---|---|
| `ssrf_encodings_rebinding_metadata` | `127.0.0.1`, decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, `[::1]`, `169.254.169.254`, CGNAT `100.64.0.1`, 6to4-relay `192.88.99.1`, IPv6-mapped `[::ffff:127.0.0.1]`, `localhost`, a trailing-dot trick; a bare DNS name; a name that rebinds to `10.0.0.5`; a public literal pinned | all blocked / name refused / rebind refused / public literal returned pinned |
| `redaction_shapes_keyname_depthbomb` | AWS key, GitHub `ghp_` token, `Authorization: Bearer ...`, DSN password, PEM private key; `password=` key-name; a 200-deep nested args bomb | all secrets collapsed; key-name redacted; depth bomb contained (no RecursionError) |
| `policy_denyfirst_roundup_modes` | `rm -rf /` in OPEN mode; `sudo ...`; `touch` under readonly; `mkfs.ext4 /dev/sdb` under guarded | deny-first denies; sudo floors T2; readonly refuses T1+; guarded refuses T3 |
| `approval_forge_replay_binding` | forged token; wrong-target binding; replay after consume | all rejected with `ApprovalError` |
| `audit_chain_tamper_detection` | tamper a middle record's value, then `verify_chain` | break detected at the exact `broken_at` index |

## Findings (register)

### F-01 Per-session execution-context isolation and atomic approval consume for the future multi-client HTTP transport (Info, latent)

- Severity: Info (latent; not reachable on the shipped transport). CWE-362 (race),
  CWE-668 (exposure across a trust boundary).
- file:line: `src/praxis/server.py::build_context` (one `ExecutionContext` per
  process), `src/praxis/execution/runner.py` (`SessionTaint` shared via the
  context), `src/praxis/execution/contract.py::ApprovalRegistry`
  (`validate` then `consume` are separate, unsynchronised steps; the registry is
  process-global).
- Evidence: `build_context` constructs a single `ExecutionContext` (hence one
  `SessionTaint` and one `ApprovalRegistry`) for the server. The stdio server's
  `serve` loop is single-process and single-threaded (`readline` then `handle`),
  and `AuditLogger` already holds a lock (BL-029), so there is no concurrency on
  the shipped path and the global latch fails safe by over-tainting.
- Exploit plausibility: none today — `server.py` refuses any non-stdio transport
  with `NotImplementedError` (fail-closed), so no second client exists. It becomes
  reachable only if/when the HTTP transport serves multiple clients on one context:
  one client's taint latch would be visible to another (the safe direction, but
  imprecise), and two threads could both pass `validate` for one single-use nonce
  before either `consume`s it, racing an approval.
- Recommended fix (for the transport work, not this pass): give each client session
  its own `SessionTaint` (and, where appropriate, its own context), and make the
  nonce check-and-burn atomic (a lock around `validate`+`consume`, or a single
  `pop`-based consume). Not covered by BL-100 or BL-101 (both now resolved)
  (request/client-id correlation), so filed as **BL-104**.
- Effort: M (lands with BL-012 HTTP serving).

### N-01 bandit B608 on the store backends (Info, no action — confirmed false positive)

- `bandit -r src -ll` flags six B608 (Medium/Low-confidence) on
  `store/sqlite.py` and `store/postgres.py`. Each is the
  `f"SELECT * FROM ... WHERE {' AND '.join(clauses)} ORDER BY seq"` shape where
  `clauses` is built only from static literal fragments (`"subject = ?"`,
  `"fact_type = ?"`, ...) and every value is bound through `params`. No attacker
  input reaches the SQL text. Ruff's `S608` is already scoped-ignored for these two
  files with a justification in `pyproject.toml`, and bandit is not a CI gate, so no
  change is made (a second suppression would be redundant; ADR-0039 Decision/
  Alternatives).

## Items verified present (no finding)

Checked and found correctly implemented this pass:

- Single audited path writes exactly one record per call including denials and
  errors; output bodies never stored (only `output_sha256` + `output_len`); the
  logger degrades to stderr and never raises; arg redaction runs first, contained,
  even before the kill switch (`runner.py`, `audit.py`).
- Append-only enforced at the storage layer on both backends (SQLite triggers +
  partial unique index; Postgres PL/pgSQL trigger functions + `BEFORE TRUNCATE`
  guard + `TRUNCATE` revoke), with `seq` uniqueness on both (BL-068/BL-091).
- Compare-and-set on both backends (`BEGIN IMMEDIATE` on SQLite, `FOR UPDATE` +
  index-race translation on Postgres), live-verified by BL-103.
- host_type gate refuses cross-type actuation as a HARD audited precondition before
  any argv is built (SEC-5).
- Trifecta containment enforced inside the runner off the shared taint latch; reads
  of observed facts arm it (SEC-4, BL-083).
- Kill switch checked on every call, durable via a sentinel, fail-closed when the
  sentinel is unreadable (SEC-8, BL-075).
- Helm chart secure-by-default: PSA-restricted, no SA token automount, default-deny
  NetworkPolicy, inline store DSN refused at render (BL-086), digest-pinned image.
- No secrets in the working tree (only the doc-example AWS key and a fake PEM in
  tests/fuzzer, by design).
