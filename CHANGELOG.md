# Changelog

All notable changes to this project are documented here. Format follows Keep a
Changelog; the project uses semantic versioning once it reaches a tagged release.

## [Unreleased]

### Added
- CIS-Talos drift baseline implemented (ADR-0028 ratifying ADR-0024, BL-099): the CIS
  Kubernetes benchmark with the Talos-defaults mapping is now drift data. `drift/cis.py`
  adds the vetted `CIS_BASELINE` (kubelet, API-server, controller-manager, scheduler,
  and cluster control families), one `normalize_value` applied identically on both
  sides, the `cis_severity` hook (any `cis:` control ranks CRITICAL), and the
  `cis_baseline_facts` / `cis_drift` / `seed_cis_baseline` helpers. A read-only
  `CisCollector` normalizes captured CIS evidence into `OBSERVED` facts and is wired
  into `ingest_observation`; `drift_scan` now passes `cis_severity`, so a seeded
  baseline plus ingested evidence reports CIS drift at CRITICAL through the existing
  audited read tools. `CIS_SUPPRESSED` waives a named baseline control and
  `TALOS_SATISFIED` documents structurally-guaranteed controls; both are excluded from
  the active set, so neither the CIS diff nor the generic scan alerts on them. No engine
  change, no new tool or UCA; the baseline is benchmark-namespaced for additive growth.
- Empty-host loopback regression test (BL-036 residual): a new
  `test_http_host_empty_defaults_to_loopback_not_open_bind` pins an empty or blank
  `PRAXIS_HTTP_HOST` to the `127.0.0.1` default and asserts the defaulted value
  classifies as loopback, so it can never reach the socket as `""` (an all-interfaces
  bind) nor be treated as a non-loopback bind the opt-in must gate. The behaviour
  landed in BL-067; this closes the named test sub-item of BL-036 (the bundle's
  agent hard-rules, values-prod overlay, namespace default-deny NetworkPolicy, and
  regulatory-deadline data remain open). Test-only; no source change.
- Helm chart unit tests gated in CI (ADR-0027, BL-032): three helm-unittest suites
  under `deploy/helm/praxis/tests/` assert the chart's load-bearing posture, the
  PSA-restricted pod/container `securityContext`, digest pinning (and the empty-digest
  `required` refusal), the `secretKeyRef`-only http token and store DSN with the BL-086
  inline-`storeDsn` refusal, the `http.allowAny` opt-in env gating, the http-gated
  `tcpSocket` probes (present for http, absent for stdio and when disabled), the
  default-deny NetworkPolicy (ingress omitted with no peer named, DNS-only egress to
  `kube-system`, the always-on `169.254.0.0/16` excision, the BL-087 bare-string and
  missing-`cidr` refusals), and the no-token-automount ServiceAccount. Gated by a
  pinned `helm-test` job in `ci.yml` (`azure/setup-helm` by SHA, helm `v3.21.0`, plugin
  `v1.1.1`) folded into the required `ci-success` aggregate, so it is required without a
  new branch-protection rule; `make helm-test` runs it locally and `.helmignore` keeps
  the suites out of the packaged chart. 26 assertions, green locally.
- Helm health probes and deploy/config cleanup (ADR-0026, BL-060): the praxis chart
  Deployment gains configurable `tcpSocket` liveness/readiness probes on the MCP port
  (a `probes` block in `values.yaml`), rendered only for the http transport (stdio has
  no listening port); `tcpSocket` is used because the MCP surface has no
  unauthenticated health route. Verified with `helm lint`/`helm template`. The
  compliance map gains a path-citation convention (module paths are `src/praxis/`-
  relative unless prefixed by a top-level dir or root file; the catalog uses the full
  form). The other BL-060 sub-items were already closed: HTTP_HOST whitespace strip
  (BL-067), `cyclonedx-bom` pin (BL-071), systemd base/drop-in de-duplication (BL-087).
- CIS-Talos drift baseline schema (ADR-0024, BL-099; Proposed): the prerequisite
  fact-predicate schema decision the backlog item requires before implementation.
  CIS controls become `KNOWN_GOOD` facts keyed on the real asset (`host:<name>` or
  `cluster:<name>`) and `cis:<benchmark>:<control_id>`, with the comparable setting in
  `value` and the CIS documentation in `reason` so the equality diff stays reliable,
  CIS-aware severity supplied through the existing `severity_for` hook (no engine
  change), and explicit, documented `CIS_SUPPRESSED`/`TALOS_SATISFIED` policy sets.
  Recorded Proposed for ratification; ratified and implemented in ADR-0028 (above).
  Documentation-only at this step.
- Audit/evidence retention tiers (ADR-0023, BL-035): `PRAXIS_AUDIT_RETENTION_DAYS`
  and `PRAXIS_EVIDENCE_RETENTION_DAYS` (default 365 days; `0` retains indefinitely;
  the anchor follows the evidence tier) bind the declared retention as the single
  source of truth and are written into the first session audit record, so the policy
  in force is part of the tamper-evident trail (NIS2 Art. 23, ISO 27001 A.8.15).
  Enforcement is storage-layer archival of whole closed files, never a runtime delete
  or in-place truncate, because the trail is append-only (invariant 4, SEC-9, SEC-10);
  `SECURITY.md`, `docs/runbooks/operate.md`, and the compliance map document the
  archive-then-rotate procedure. Implements ADR-0011 finding 035. Also refreshed the
  stale BL-076 note on the NIS2 Art. 23 compliance row (runtime checkpoints now ship;
  the residual is the keyless `LocalStamper`, BL-095).
- STPA traceability completion (ADR-0022, BL-089): every UCA-1..28 now appears in a
  SEC "Prevents" column in `docs/stpa/07-security-constraints.md`. The already-enforced
  actuation UCAs are listed under their covering constraints (UCA-4/UCA-6/UCA-10 under
  SEC-2 minted approval; UCA-4..UCA-7 under SEC-6 human-gated convergence; UCA-10 under
  SEC-5 talosctl one-target T3). The mode-ceiling escalation (UCA-23) is covered under
  SEC-3: there is no runtime `set_mode` tool, the mode is bound once at startup and
  `Policy.check` applies it uniformly, and a new proving test
  (`test_mode_ceiling_cannot_be_escalated_per_tool`) asserts no tool name, command, or
  declared `base_tier` lifts a call past the ceiling and that a mode refusal is not
  approval-gated. The planned `act_redfish`/`act_cloud` adapters have no implementation
  in this version, so their UCAs (UCA-12/13/14) are pre-staged and flagged `[planned]`
  in `05-ucas.md` and `(planned ...)` in the SEC table; the flags clear when the
  adapters land. SEC-3's catalog statement and proving-test list are updated to match,
  keeping the ADR-0021 compliance validator green. No runtime behavior changes.
- Machine-checkable compliance catalog (ADR-0021, BL-031; advances BL-036): the
  prose compliance map and the STPA security constraints are projected into
  `docs/governance/compliance-controls.json`, a pydantic-validated catalog keyed by
  the SEC-1..SEC-10 ids plus one governance control. `scripts/validate_compliance.py`
  (`make validate-compliance`, in `ci-success` and re-run by the suite) enforces
  eleven bidirectional rules: id format, SEC-to-STPA completeness, module existence
  and `SEC-N` back-citation, no dangling `SEC-N` token in the source tree, invariant
  range, framework coverage, proving-test existence (an implemented control names at
  least one), prose-map parity, and status/tracking coherence. The model is the
  source of truth for a generated
  `docs/schema/compliance-controls.schema.json` under the schema-drift guard.
- Content-hash compare-and-set for the store (ADR-0021, BL-027): a `VersionedStore`
  extension Protocol (`Capability.COMPARE_AND_SET`) with `put_fact_if(fact,
  expected_version=...)`, gated on `Fact.content_hash`. SQLite takes the write lock
  up front (`BEGIN IMMEDIATE` plus `busy_timeout`), Postgres locks the active row
  (`SELECT ... FOR UPDATE`); a stale version raises `VersionConflict` and writes
  nothing, foreclosing a lost update on a human-gated supersede (SEC-6, invariant 4).
  The Postgres create-if-absent race (no row to lock) is translated from a unique-index
  violation to `VersionConflict` so the create path honours the contract (live-PG
  verification tracked as BL-103). A SQLite concurrency test proves exactly one of
  two racing writers wins; the rest run in the backend-parity suite.
- Talos partition-scoped reset (ADR-0021, BL-098): an additive `system_labels` param
  on the talosctl adapter mapping to `reset --system-labels-to-wipe` (allowlisted
  `EPHEMERAL`/`STATE`), preserving the `STATE` partition so a node rejoins instead of
  needing a full re-provision. Mutually exclusive with `--wipe-mode` (both refused);
  the documented `system-disk` default (BL-025) is unchanged; the reset stays T3.

### Security
- Rebinding-aware SSRF egress resolution (ADR-0025, BL-046): a new
  `resolve_and_assert_egress_allowed` in `src/praxis/_ssrf.py` resolves a URL host
  once, checks EVERY resolved address against the blocked ranges, fails closed (an
  unresolvable host, an empty answer, an unparseable address, or any blocked address
  raises), and returns the vetted IP literals so the caller pins the connection and
  never re-resolves between check and connect (the DNS-rebinding defence, SEC-7).
  It is additive: the strict `assert_egress_allowed` (deny bare names) default is
  unchanged, so nothing is weakened; a host-resolving egress consumer opts in. The
  "wire into the egress path" half of BL-046 stays open until a server-initiated
  egress consumer exists (HTTP transport BL-012 or a cloud/redfish adapter); none
  does in v0. The resolver seam is injectable; seven regression tests cover the
  rebinding, multi-IP, fail-closed, IP-literal, and userinfo-mask cases.
- Redaction hardening (ADR-0021, BL-097): `execution/redaction.py` adds the PyPI
  upload-token shape, runs the npm and GitLab token bodies unbounded from their
  length floor so a longer token collapses whole (no audit-log tail), and adds a
  context-gated compact MySQL `-p<password>` redaction that fires only when a
  MySQL-family client is present (so `-p`-as-port for `ssh`/`nmap` is not
  over-scrubbed). Strengthens SEC-9; no `PATTERNS_VERSION` change.
- SSRF bypass sweep and 6to4 relay block (ADR-0020, BL-061, BL-096): an
  adversarial pass over the egress filter confirmed IPv4-in-IPv6 (v4-mapped,
  NAT64, 6to4), IPv6 special ranges, URL userinfo masking, and bracketed v6
  literals are all blocked; the one gap, the deprecated 6to4 relay anycast
  `192.88.99.0/24` (RFC 7526, classified inconsistently across interpreter
  patch versions), is now blocked with a deterministic constant. Regression
  sweep added.
- Deploy hardening (ADR-0020, BL-087 partial): the systemd drop-in adds
  `PrivateUsers`/`ProcSubset=pid`/`RemoveIPC` and is de-duplicated against the
  base unit; the Helm NetworkPolicy scopes DNS egress to `kube-system` and makes
  `networkPolicy.egressCIDRs` `{cidr, except}` objects that always excise
  `169.254.0.0/16` (cloud metadata/link-local). The bare-string `egressCIDRs`
  form is refused at render time. `IPAddressDeny`/`SocketBindDeny` stay
  operator-scoped (a deny-all default would brick SSH actuation).
- Runtime evidence production (ADR-0019, BL-076, BL-050, BL-030): with an audit
  file configured the server now produces Merkle checkpoints every
  `PRAXIS_EVIDENCE_EVERY` records (default 64) and at orderly shutdown, into
  `PRAXIS_EVIDENCE_PATH` (default `<audit>.evidence.jsonl`); with
  `PRAXIS_ANCHOR_PATH` set, each checkpoint head is appended to an owner-only
  anchor file and `verify_evidence`/`verify_audit.py` cross-check it, so
  rewriting both the log and the evidence file to a shorter consistent history
  is detected (the BL-050 attack; tamper-matrix tests cover it with and without
  the anchor). Evidence production is contained: a failing checkpoint or anchor
  write warns on stderr and never loses, blocks, or breaks an audit record.
  Ingested snapshot hashes (`raw_sha256`, BL-085) are now Merkle-committed by
  composition (BL-030). The keyless `LocalStamper` remains the default; the
  non-forgeable RFC 3161/Rekor stamper is split out as BL-095, and OS-level
  append-only storage stays the documented required control.
- Audit self-consistency (ADR-0018, BL-094): `AuditLogger.record` now normalizes
  the payload through one canonical JSON round-trip before hashing, so the
  `entry_hash` and the written line always derive from the same rendering.
  Previously the hash covered `str()` of the live args while the written line
  carried `str()` of a deep copy; for a copy-sensitive value (a set, under some
  hash seeds) an honest record failed its own hash and `verify_chain` reported
  tampering. Found by the new coverage gate re-running the suite; deterministic
  regression test added.
- Postgres storage-layer parity (ADR-0018, BL-091, BL-028): `seq` is computed
  inside the INSERT under new unique indexes, so the cross-instance `MAX(seq)+1`
  race fails loudly with a `UniqueViolation` instead of silently corrupting fact
  ordering (the BL-068 fix had covered SQLite only); a statement-level
  `BEFORE TRUNCATE` trigger refuses table-wide truncation, with `TRUNCATE` also
  revoked from `PUBLIC`. Live-verified against PostgreSQL 16.13; new live tests
  (seq uniqueness across two store instances, duplicate-seq violation, TRUNCATE
  and DELETE refusals) run when `PRAXIS_TEST_PG_DSN` is set, and static schema
  guards assert the same statements without a database.
- Supply chain (ADR-0018, BL-088): CI installs are hash-locked
  (`requirements-dev.txt`, consumed with `pip --require-hashes`); the dev,
  postgres, and build-backend requirements are version-bounded so majors cannot
  land unreviewed; the fuzz workflow runs on a test-matrix interpreter (3.13);
  the SBOM is generated against a dedicated venv so it describes the production
  dependency graph, not the runner environment.
- Helm hardening (ADR-0018, BL-051, BL-086): NetworkPolicy ingress admits only
  the peers named in `networkPolicy.ingressFrom` (empty default denies all
  ingress to the MCP port); the PostgreSQL DSN moves to a `secretKeyRef`
  (`store.existingSecret`/`store.secretKey`), and an inline `storeDsn` now fails
  the render with a migration message instead of landing the password in etcd
  and `helm history`. Verified with helm 3.21 lint plus rendered-output checks.

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
- Test and fuzz expansion (ADR-0020, BL-061): the full adapter x host_type
  refusal matrix, a SQLite/Postgres backend parity suite over the shared
  bitemporal behaviors (live-verified against PostgreSQL 16.13), and
  `scripts/fuzz.py` stages for the SKILL.md frontmatter parser, the Merkle tree,
  and `verify_evidence`.
- ADR-0020 (Accepted): test/fuzz expansion and deploy hardening; resolves
  BL-061 and BL-096, advances BL-087.
- ADR-0019 (Accepted): runtime evidence and the anchored high-water mark;
  resolves BL-030, BL-050, and BL-076; files BL-095. New config:
  `PRAXIS_EVIDENCE_PATH`, `PRAXIS_EVIDENCE_EVERY`, `PRAXIS_ANCHOR_PATH`;
  `verify_audit.py` takes the anchor as an optional third argument; SECURITY,
  LIMITATIONS, README, the self-audit runbook, and the systemd unit updated.
- Coverage floor on the aggregate gate (ADR-0018, BL-053): `make coverage`
  (source-based, `fail_under = 90`, measured 91 without the postgres extra)
  joins `ci-success`; the entry point gained tests for the fail-closed
  `TransportError` to `SystemExit` refusal and the import-bound CONFIG.
- Chart `NOTES.txt` and a values warning that v0 refuses non-stdio transports,
  so the default chart CrashLoopBackOffs until HTTP serving lands (BL-093).
- ADR-0018 (Accepted): the remediation wave resolving BL-028, BL-051, BL-053,
  BL-086, BL-088, BL-091, and BL-093.
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
