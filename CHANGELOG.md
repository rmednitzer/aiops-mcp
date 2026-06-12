# Changelog

All notable changes to this project are documented here. Format follows Keep a
Changelog; the project uses semantic versioning once it reaches a tagged release.

## [Unreleased]

### Security
- Human-binding approval gate (ADR-0016, BL-072, closes the ADR-0015 P1 finding):
  a gated DRY_RUN now mints a server-generated, single-use, TTL-bound nonce
  (bound to action id, target, tier, and `PATTERNS_VERSION`) surfaced out-of-band
  on the operator console; the deterministic `expected_token` and its echo in the
  DRY_RUN response are removed, so an autonomous caller can no longer self-approve
  T2/T3 actions. A restart invalidates pending nonces (fail closed).
- Free-form shell floors at T2 (ADR-0016, BL-073): `SSHAdapter.base_tier` raised
  from T1 to T2; `PATTERNS_VERSION` bumped to 3 with new destructive patterns
  (`find -delete`, `iptables -F`/`--flush`, `nft flush ruleset`, `kubectl
  drain`/`cordon`/`uncordon`, SQL `DELETE`/`UPDATE` without `WHERE`, Windows
  `Remove-Item -Recurse`/`Format-Volume`/`Stop-Computer`, `authorized_keys`
  appends, `ssh-copy-id`).
- Trifecta containment enforced inside the single audited path (BL-083, BL-084):
  the session taint latch is shared between `ServerContext` and the execution
  core; once armed, any T1+ real run requires a minted approval, validated and
  consumed in one place. The handler-level gate (`guard_actuation`,
  `TrifectaViolation`) is removed. Reads that return observed facts arm the
  latch (BL-062 sharpening); `ExecutionRequest.untrusted` is now load-bearing.
- Actuation input hardening: ansible/runbook paths confined to configured roots,
  fail closed when unset (`PRAXIS_PLAYBOOK_ROOT`, `PRAXIS_RUNBOOK_ROOT`; BL-024,
  BL-081); ansible `--limit` host validated (BL-081); talosctl refuses post-verb
  option tokens (closing `--talosconfig` and `--recover-skip-hash-check`
  injection, BL-082, BL-022), validates nodes/endpoints as IP or RFC 1123 names
  (BL-082), always passes an explicit `--wipe-mode` for reset defaulting to
  `system-disk` (BL-025), and gates real-run upgrades on a `talosctl health`
  HARD precondition (BL-023).
- Subprocess environment is an allowlist: unrelated server secrets no longer
  reach wrapped tools or their plugins (BL-080).
- Audited-path containment: `redact_args` is depth-bounded and a redaction
  failure audits-and-denies instead of raising unaudited (BL-077); the audit
  canonicalizer uses `default=str` so the logger never raises on non-native arg
  values (BL-078); audit appends are serialised under a lock (BL-029).
- Store hardening: the SQLite file is pre-created `0o600` (BL-079); `seq` is
  computed inside the INSERT under a unique index, so a cross-instance race
  fails loudly (BL-068).
- stdio protocol hardening: per-line read bounded at 16 MiB with oversize drain,
  notifications (no `id` member) never receive a response, deeply nested JSON is
  contained (BL-056). Collectors parse numerics finite-or-default (BL-026).
- Classification probe includes the tool name; stdin/env passthrough documented
  as a channel that must never be added unclassified (BL-019).

### Added
- ADR-0016 (Accepted): approval hardening and enforcement wave, ratifying
  ADR-0015 Decisions 3a and 3b; resolves BL-017, BL-019, BL-022..BL-026, BL-029,
  BL-049, BL-056, BL-062, BL-068, BL-072..BL-085, and BL-090, each with a
  regression test.
- `emergency_stop` MCP tool and a durable kill-switch file sentinel
  (`PRAXIS_KILL_SWITCH_PATH`): the trip is audited, never approval- or
  budget-gated, survives a restart, and is restorable only out-of-band (BL-075).
- Per-session budget enforcement on the audited path (`PRAXIS_MAX_ACTIONS`,
  `PRAXIS_MAX_WALL_SECONDS`): a T1+ real run that passed every gate charges an
  action just before executing and records wall time after; exhaustion is an
  audited denial, and a refused approval never burns the ceiling (BL-074).
- `CredentialBroker` wired into the server context and bound to the kill switch:
  zero grants keeps the single-operator default; the first grant flips actuation
  to deny-unless-authorized via a HARD audited precondition (BL-049).
- All read tools and `ingest_observation` route through `run()` via a shared
  `run_audited` helper, so every tool call writes exactly one audit record; the
  ingest audit carries `raw_sha256`/`raw_len`, never the telemetry body (BL-017,
  BL-062, BL-085).
- `run_action` gains a structured `wipe_mode` parameter for talosctl reset;
  schemas regenerated for the new tool surface.
- ADR-0017 (Accepted): full audit, validation, and hardening pass (2026-06-12),
  read-only, recorded under `audit/` (inventory, baseline, findings register,
  final report). Re-validated the green baseline (226 passed, all gates green;
  `pip-audit` clean; no secrets in tree or history; fuzz 200000 iterations clean;
  README quickstart executes). No critical/high/medium findings. Files BL-091
  (Postgres `seq` race residual not closed by BL-068), BL-092 (no reviewable
  Dockerfile behind the referenced image), and BL-093 (Helm `transport: http`
  default crash-loops in v0). No code change: the one actionable finding is a
  deferred Postgres schema proposal.

### Changed
- Documentation honesty pass (ADR-0015): README, SECURITY, LIMITATIONS,
  architecture, the compliance map, the STPA constraint table, the operate and
  self-audit runbooks, and the deploy README now state the v0 enforcement gaps
  plainly (the approval token is not yet human-binding, free-form shell floors at
  T1, the read tools and `ingest_observation` bypass the audited path, and the
  credential broker, budgets, kill-switch actuator, and runtime audit anchoring are
  not yet wired). Appended factual audit notes to the immutable ADR-0004, ADR-0005,
  and ADR-0008. No code or control changed.

### Added
- ADR-0015 (Proposed): deep security and architecture review (2026-06) and the
  proposed remediation wave BL-072..BL-090. Records two architectural proposals
  for ratification (a human-binding, server-issued approval nonce in place of the
  deterministic token; a T2 tier floor for free-form shell, runbook, and exec
  actuation), the latent-control wiring set (`CredentialBroker`, `BudgetTracker`,
  the kill-switch actuator, runtime audit anchoring), and the STPA and
  compliance-map traceability gaps. Documentation-only; no code or control was
  changed.
- Governance-first bootstrap scaffold: repository layout, `CLAUDE.md`,
  `AGENTS.md`, `README.md`, `SECURITY.md`, `LIMITATIONS.md`, `CONTRIBUTING.md`.
- ADR-0001 and the ADR index, the `docs/stpa/` skeleton, `docs/backlog.md` seed,
  the compliance-map skeleton, and a seed fleet inventory example.
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
  `LocalStamper` default; real TSA staged), `verify_evidence` (hash chain + Merkle +
  checkpoint chain + token, fail-closed), a session header binding the
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
- Third audit-wave hardening (ADR-0013, BL-018/020/021/034/047/048/054/055/057/058/
  059 resolved, BL-063 to BL-067 new); each fix ships with a regression test:
  - SSH actuation now forces a host-key policy and `BatchMode=yes` into the argv
    (`StrictHostKeyChecking=accept-new` by default, refusing a changed key;
    `ConnectTimeout`), and refuses a target that is not alphanumeric-leading so a
    `-oProxyCommand=...` host can never be parsed as an ssh option (BL-020).
  - The actuation subprocess runs in its own session (`start_new_session=True`)
    with stdin detached (`DEVNULL`) and a scrubbed environment
    (`GIT_TERMINAL_PROMPT=0`, `DEBIAN_FRONTEND=noninteractive`, neutralised
    `*_ASKPASS`), and on timeout the whole process group is killed, so a wrapped
    tool cannot read the MCP stdio stream, hang on a prompt, or leak a grandchild
    tree (BL-021, BL-063).
  - talosctl enforces the T3 one-target-at-a-time rule on the actual `host.nodes`
    (a multi-node reset/upgrade is refused), and constrains the leading verb to an
    allowlist instead of tokenising a free-form action (BL-047, BL-048).
  - A trifecta refusal now writes a `denied` audit record before it raises, so the
    refusal is never silent (BL-018).
  - The audit logger keeps writing to the file on a corrupt tail (resuming at
    genesis, a visible seam the verifier reports) instead of dropping the sink to
    stderr, never reopens after a degrade, releases the handle on close, and creates
    the log `O_APPEND` and owner-only (`0o600`) (BL-055, BL-064).
  - Vector search skips a non-finite (`NaN`/`inf`) stored embedding and refuses a
    non-finite query, so a poisoned vector cannot poison the ranking (BL-054).
  - The SKILL.md frontmatter parser requires an exact `---` fence, caps the header
    and file size, ignores indented keys, refuses a duplicate key, and treats
    non-UTF-8 bytes as a clean load failure (BL-057).
  - An empty or unparseable AIDE report is no longer reported as a clean host
    (`clean` requires positive evidence of a completed run), and the ingest tool
    bounds collected telemetry before a collector parses it (BL-058).
  - `parse_ansible_check` surfaces `FAILED`/`UNREACHABLE` hosts (critical), not only
    `changed:` (BL-034); an `UNEXPECTED` drift on a security predicate (a rogue port
    or user) escalates to critical instead of info (BL-059).
  - Redaction covers more provider token shapes (`github_pat_`, `glpat-`, `npm_`,
    `AIza`, `ya29.`, Stripe, OpenAI scoped) and redacts the whole `Authorization`
    value to end-of-line, so a comma-separated AWS SigV4 signature no longer leaks
    (BL-065).
  - `PRAXIS_HTTP_HOST` is whitespace-stripped so a `"127.0.0.1\n"` value is still
    recognised as loopback by the transport guard (BL-067).
- Self-containment (BL-066): removed the out-of-tree prototype reference from
  `context.py`; praxis names no sibling repository in code or docs (ADR-0001).

### Changed
- `ingest_observation` is annotated `read_only=false`: it writes (append-only)
  observed facts to the model, so the MCP annotation now reflects that. The
  generated `docs/schema/tools.schema.json` is regenerated accordingly.

### Fixed
- SBOM workflow (`.github/workflows/sbom.yml`): the CycloneDX generator step failed
  with `cyclonedx-py: error: unrecognized arguments: --outfile`. The
  `cyclonedx-py environment` subcommand's output flag is `--output-file`, not
  `--outfile`, so the job had failed on every push to main since the workflow was
  added. It runs only on push to main and on a weekly schedule (never on
  pull-request checks), so the breakage never surfaced on a green PR. Corrected the
  flag; pinned `cyclonedx-bom==7.3.0` so a future unpinned major bump cannot
  silently change the CLI surface (closes the `cyclonedx-bom` pin in BL-060); and aligned the
  SBOM runner to Python 3.12 (the `requires-python` floor and the ci.yml matrix)
  rather than a bleeding-edge interpreter (BL-071).

### Dependencies
- Adopted `pydantic` (MIT) as a core runtime dependency for declarative validation at
  the external-input boundary, and clarified the dependency posture (ADR-0014,
  BL-069, BL-070):
  - The self-contained rule means no coupling to a sibling fleet repository, not
    "no third-party libraries". `pydantic` joins the optional `psycopg`; the
    execution core (`patterns`/`policy`/`redaction`/`audit`/`contract`/`runner`) and
    the fact model stay dependency-free. An appended audit note on the immutable
    ADR-0001 records the clarification.
  - Each MCP tool now has a typed args model (`ToolArgs` subclass) that is the single
    source of truth for both the advertised JSON Schema and the parse/validate step.
    The registry validates a `tools/call` argument set through the model at one
    boundary: an out-of-shape, missing, unknown-enum, or unexpected (`extra='forbid'`)
    argument is rejected as a bounded tool error instead of reaching a handler. The
    committed `docs/schema/tools.schema.json` is generated from the models.
  - `config.Config` is a frozen pydantic model; `validate_transport` remains the
    fail-closed transport authority and import stays non-raising.
  - The SKILL.md frontmatter is validated through a `SkillFrontmatter` model (also the
    `skill-manifest.schema.json` source); the hardened parser (BL-057) is retained and
    validated, not replaced.
  - The over-absolute "implements everything itself" wording is corrected across
    `CLAUDE.md`, `AGENTS.md`, `README.md`, `CONTRIBUTING.md`, and `docs/architecture.md`.

### Removed
- Retired `docs/first-session.md` (the one-time build brief, now that v0 is built).
  Its durable content (the mission, the strict layering, the repository layout, and
  the trusted external sources) moved to a current-tense `docs/architecture.md`;
  `CLAUDE.md`, `AGENTS.md`, `README.md`, and the ADR index point there. The nine
  invariants remain in `CLAUDE.md`.
