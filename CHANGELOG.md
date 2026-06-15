# Changelog

All notable changes to this project are documented here. Format follows Keep a
Changelog; the project uses semantic versioning once it reaches a tagged release.

## [Unreleased]

### Security
- Deep audit, validation, and adversarial-testing pass (ADR-0040, the parallel deeper
  pass alongside the ADR-0039 refresh; recorded under `audit/2026-06-14/`). No critical or
  high findings; the nine invariants and the STPA traceability re-validated (compliance
  validator 0 violations; fuzz 20000 iterations clean). Six findings remediated in-pass,
  each with a regression test: the audit canonicaliser now never raises on a hostile
  `__str__` or a circular reference (F-001); redaction covers Anthropic (`sk-ant-`),
  HuggingFace (`hf_`), and DigitalOcean (`do[opr]_v1_`) tokens (F-006); `supersede` checks
  the UPDATE rowcount on both store backends so a concurrent loser no longer gets a false
  success (F-007); the `rm -rf /` deny now also catches `//`, `/*`, and `/.` (F-004,
  `PATTERNS_VERSION` 3->4); the Talos non-JSON status fallback is length-capped (F-008);
  the OpenTofu adapter no longer passes an unconfined `chdir` (F-003, safe re-add tracked
  as BL-105). Three dispositions are documented (F-002 pattern-based redaction; F-005
  operator-trusted syslog destination; F-009 ADR-0015 ratification note). Deferred
  hardening filed as BL-105..109. Prose docs brought current (architecture, README,
  SECURITY, LIMITATIONS, runbooks, compliance map).
- `cryptography` is bounded in lockstep across the `tsa` and `dev` extras (`>=49,<50`),
  with the exact pin in the hash-locked `requirements-dev.txt` at 49.0.0. Keeping both
  bounds aligned closes a recurring hazard: a dependency bot that bumps the `tsa` extra
  and the lock but leaves the duplicate `dev` bound behind makes the two contradict each
  other, so a lock regeneration silently changes the installed version (it surfaced
  first with the v46 advisory fix in #55/#57, and again after the v49 bump in #53, which
  left the `dev` bound at `>=46.0.7,<47` while the lock moved to 49.0.0; realigned in
  #62). The suite, including the BL-095 stamper verification, passes on cryptography
  49.0.0.

### Documentation
- Fixed a GitHub Pages rendering bug on the Backlog page (2026-06-15). The `BL-NNN`
  resolution/audit notes were written as `<!-- ... -->` HTML comments interleaved between
  table rows; a block-level comment terminates a Markdown table, so MkDocs (python-markdown)
  rendered only the first dozen rows as a table and the remaining ~99 rows as a wall of raw
  `| ... |` text. The notes are relocated below the table (still hidden HTML comments, content
  unchanged) so the table renders as one contiguous table. No `BL` rows or note text were lost.
- Documentation-currency and consistency audit pass (2026-06-15), following the ADR-0043
  merge. STPA brought in line with the merged ADR-0043 (which states the planned UCAs are
  pre-staged): `docs/stpa/05-ucas.md` gains the `act_kubectl` (UCA-29, UCA-30) and
  `act_helm` (UCA-31) `[planned]` rows, `docs/stpa/07-security-constraints.md` maps them
  under SEC-2 (approval and pipeline order) and SEC-5 (host_type gate plus the
  `exec`-plugin/unscoped-kubeconfig refusal), and the coverage prose moves from UCA-1..28
  to UCA-1..31; the compliance gate (`make validate-compliance`) stays green. `README.md`'s
  status blurb no longer claims the backlog is fully resolved (it names BL-111 as the one
  open, forward-looking item). `LIMITATIONS.md` gains a Kubernetes/Helm actuation gap, and
  the `praxis.actuation` package docstring notes kubectl/helm are staged behind the ADR-0043
  scoped-kubeconfig contract. `mkdocs.yml`'s ADR-count comment moves 42 to 43, and a
  `BL-106/106` typo in `audit/2026-06-14/02-report.md` is corrected to `BL-106/107`. The
  living docs and code comments were otherwise verified current (43 ADRs, six registered
  tools, HTTP delivered, the HostType enum unchanged); immutable ADR bodies and dated
  `audit/` snapshots are left intact as point-in-time records. Validation: `make ci-success`
  (ruff + mypy strict + pytest + schema-drift + eval + compliance + coverage) and
  `mkdocs --strict` green. No code behavior change.
- ADR-0043 (Proposed): the Kubernetes actuation credential contract. Records the dividing
  line for whether `kubectl`/`helm` can become first-class audited actuators or must stay
  bastion-host skills, decided by the credential model (invariants 8 and 9). A first-class
  adapter is admissible only under a scoped-static-kubeconfig contract: an RBAC-scoped,
  non-admin kubeconfig referenced out of band via the already-allowlisted `KUBECONFIG`; a
  new `HostType.KUBERNETES` carrying the kubeconfig path and context pinned from trusted
  inventory (`confine_to_root` paths); `exec`-stanza (cloud/OIDC) kubeconfigs refused
  fail-closed because they need ambient credentials `scrubbed_env()` strips and run an
  arbitrary per-call subprocess; a verb allowlist with native `--dry-run`; the SEC-5
  host_type gate; and pre-staged `act_kubectl`/`act_helm` UCAs. Cloud/`exec`-auth clusters
  stay a bastion skill; ArgoCD is kept out of actuation (it overlaps the human-gated drift
  engine, ADR-0007). The ADR builds nothing: with no KUBERNETES host and no adapter
  registered the default posture and dependency set are unchanged. Indexed in
  `docs/adr/README.md`; implementation tracked as BL-111.
- Documentation-currency pass: brought the prose and code comments into line with the
  delivered state after ADR-0041/0042, the six registered tools, and the fully resolved
  backlog. `docs/architecture.md` now describes HTTP serving as delivered (ADR-0041) and
  concurrent (`ThreadingHTTPServer` over a thread-safe store, ADR-0042) and lists the
  correct six-tool grouping, replacing the stale "staged, raises `NotImplementedError`,
  serves stdio only" text and a nonexistent "skills (read)" MCP group. `README.md`'s
  status blurb drops the pre-ADR-0016 "specified but not yet wired" framing and the
  "open work in `docs/backlog.md`" claim (the backlog is fully resolved).
  `deploy/README.md` and `deploy/RELEASE-CHECKLIST.md` no longer describe HTTP serving as
  pending. `LIMITATIONS.md` corrects the wave range to ADR-0042 and "the five registered
  tools" to six. The `praxis.server` and `praxis.tools` module docstrings match the
  current transport and tool surface. No code behavior change.

### Added
- A complete how-to guide (`docs/guide.md`, in the docs-site nav): a task-oriented walk
  through running the server, the MCP protocol surface (`initialize` / `tools/list` /
  `tools/call`), and every one of the six tools (`query_facts`, `fact_history`,
  `drift_scan`, `ingest_observation`, `run_action`, `emergency_stop`) with argument tables
  and request/response examples drawn from the actual validated schemas. Covers the mental
  model (tiers, modes, the DRY_RUN to approve to execute flow, the trifecta latch, the
  audit), end-to-end observe and actuate workflows, the common refusals, the HTTP transport
  (auth, sessions, consent ceiling), a `PRAXIS_*` configuration reference, and audit
  verification.
- Documentation site (MkDocs Material) published to GitHub Pages by a new
  `.github/workflows/pages.yml`. The site renders `docs/` (architecture, the 42 ADRs via
  their index, the STPA hazard analysis, the governance/compliance map, the runbooks, the
  roadmap, and the backlog) with search and light/dark themes, from a new `docs/index.md`
  landing page and `mkdocs.yml`. The toolchain is a docs-only `docs` extra, hash-locked in
  `requirements-docs.txt` (Renovate-maintained, like the dev lock) and installed only in the
  Pages CI job, so the package and the dependency-free execution core are unchanged
  (ADR-0001/0014). The workflow is least-privilege (only the deploy job holds `pages: write`
  + `id-token: write`), pins every action by commit SHA, builds `--strict` (PRs validate the
  build without deploying), and serializes deploys with a `pages` concurrency group. Local
  build/preview via `make docs` / `make docs-serve`. Publishing requires GitHub Pages with
  the "GitHub Actions" source (the first run auto-enables it via `configure-pages`, or set it
  once in Settings -> Pages).
- Future-expansion roadmap for IAM, access control, and secrets
  (`docs/roadmap/iam-access-and-secrets-expansion.md`): an exploratory, standards-grounded
  study (MCP 2025-11-25 authorization, NIST SP 800-207 PDP/PEP, NIST SP 800-162 ABAC/RBAC,
  SPIFFE/SPIRE, Vault dynamic secrets, OPA/Cedar) of a per-principal identity and policy
  layer, should praxis ever move beyond its single-operator target. It records the value
  verdict (net-negative for single-operator today; high value on a multi-operator trigger),
  the non-negotiable constraints (identity sits above the existing gates, default-closed,
  dependency-free core, no IdP/secret store in-tree, authz never consumes collected facts),
  a five-phase additive plan, and an adversarial analysis. Not a decision; promoted to an ADR
  plus backlog only on trigger. Linked from `LIMITATIONS.md`, whose stale "consent ceiling
  not implemented" gap is corrected (delivered in ADR-0041).
- BL-110 concurrent HTTP serving (ADR-0042): the HTTP transport now serves each request
  on its own thread (`ThreadingHTTPServer` with `daemon_threads`), so a slow actuation on
  one client no longer blocks the others. Every store method serialises on a per-instance
  re-entrant lock (a `synchronized` decorator in `store/base.py` over `SqliteStore`, opened
  `check_same_thread=False`, and `PostgresStore`), and the `BudgetTracker` check-and-charge
  is atomic, so the bitemporal/append-only invariants and the per-session budget hold under
  concurrency; the audit hash chain and the evidence scheduler were already lock-guarded,
  and the taint latch and kill switch stay lock-free (monotonic, fail-safe). Per-instance
  locking keeps the BL-103 two-instance compare-and-set test exercising real cross-connection
  concurrency. Covered by new concurrency tests in `tests/store/test_store_hardening.py`,
  `tests/execution/test_contract.py`, and `tests/test_http_server.py`.
- BL-105 OpenTofu workspace `-chdir`, confined (ADR-0040): the OpenTofu adapter re-adds
  `tofu -chdir=<dir>`, confined to `PRAXIS_TOFU_ROOT` (the `tofu_chdir` `run_action` arg),
  the same fail-closed pattern as the ansible/runbook roots; `confine_to_root` gains an
  additive `require="dir"` mode. A chdir with no root, an escaping path, or a missing or
  non-directory target is refused. The unconfined passthrough removed as F-003 is now a
  safe, opt-in capability.
- BL-108 per-pair/per-value caps in `CommandProbeCollector.parse` (ADR-0040): the parser
  bounds the pair count and per key/value length (silent truncation, never-raises),
  defense-in-depth against a hostile probe within the 4 MiB output ceiling (invariant 8).
- BL-109 compliance-catalog note (ADR-0040): an additive optional `notes` field on the
  catalog records that `proving_tests` lists at least one representative test per control
  (validator rule R9), not the exhaustive set, which the STPA 07 tables enumerate.
- BL-012 multi-client HTTP transport (ADR-0041): the HTTP serving loop that was staged
  behind the always-enforced transport guard is now delivered (`src/praxis/http_server.py`),
  opt-in via `PRAXIS_TRANSPORT=http` and still default-closed (token + non-loopback opt-in
  + SSRF egress, ADR-0006). Stdlib `http.server` only (no new dependency). `initialize`
  mints an `Mcp-Session-Id` and a per-session `ServerContext` that shares the one audit
  hash chain, the store, and the global kill switch but has its own trifecta taint latch,
  approval registry, budget, and consent ceiling, so one client cannot taint another or
  race another's approval (BL-104). Every request carries `Authorization: Bearer` compared
  in constant time (BL-106) and a Content-Length-capped body (BL-107); a session may pin a
  per-client tier ceiling via an `initialize` `consentCeiling` param, enforced in the
  audited path (ADR-0006 Decision 4 / BL-045). `ApprovalRegistry` is now lock-guarded with
  an atomic check-and-burn and constant-time, byte-based token matching. The minted
  approval nonce still surfaces on the server console (never in the HTTP response), so the
  human-binding gate holds over HTTP. Single-threaded in v1 (the SQLite store is one
  connection); concurrent serving over a thread-safe store is tracked as BL-110. Covered by
  `tests/test_http_server.py` and the approval/consent tests in
  `tests/execution/test_contract.py` and `tests/execution/test_runner.py`.
- Second full-pass audit (2026-06-14), recorded as ADR-0039: the `audit/00..03` evidence files are refreshed with fresh command-backed validation on the merged tree (372 passed / 23 skipped, all gates green, 92% coverage, pip-audit clean, `fuzz 200000` clean) and a new executed adversarial battery (SSRF encodings/rebinding, redaction, deny-first policy, approval forgery/replay, audit-chain tamper -- 5/5 controls held). Every 2026-06-12 finding (BL-091/092/093 and the BL-088 items) is confirmed closed and the concurrently-merged #69 (multi-sink) and #71 (correlation) deltas reviewed. One Info/latent forward-looking item is filed as BL-104 (per-session execution-context isolation + atomic approval consume for the future multi-client HTTP transport); no code change.
- BL-101 resolved (ADR-0038): optional request/client correlation on the audit record.
  `AuditRecord` and `AuditLogger.record` gain two additive fields, `request_id` and
  `client_id` (default None), inside the hashed payload so they are tamper-evident and
  `verify_chain` stays consistent. They are threaded ambiently via a new
  `execution/correlation.py` (`request_scope` set by the transport;
  `current_request_id`/`current_client_id` read by `run`'s audit helper), so no tool
  signature changes and they are absent outside a request scope. The stdio transport
  binds the JSON-RPC request id as `request_id` around the `tools/call` dispatch;
  `client_id` stays None for the single-client stdio transport and is set by a
  multi-client transport (HTTP, BL-012). The client-supplied id is coerced, stripped, and
  truncated to 128 chars by `bound_id`, which never raises, so a hostile client cannot
  bloat a record. Covered by `tests/execution/test_correlation.py`; `correlation.py` at
  100%, the audit module at 96%.
- BL-100 resolved (ADR-0037): the audit log is now multi-sink. A new optional
  secondary sink, `SyslogAuditSink`, forwards each canonical, already-redacted audit
  line to syslog for SIEM / journald visibility (a Unix socket path such as `/dev/log`,
  or `host:port` for a remote UDP collector), opt-in via `PRAXIS_AUDIT_SYSLOG_ADDRESS`
  (default unset, so the single file sink is unchanged). A new `MultiSink` applies the
  `skills/dispatch` fan-out class to the audit write side: it fans one line to N
  secondary sinks, contains a per-sink `Exception` (noting a persistently failing sink
  once per streak, not per record) so one failing sink cannot silence the others, lets
  `BaseException` propagate, and never raises (invariant 3). The append-only
  hash-chained file stays authoritative, written first and directly; secondaries are
  best-effort forwards fanned out after it, so a failing, slow, or oversized secondary
  can never affect the primary write, the hash chain, the `seq`, or `verify_chain`.
  Covered by `tests/execution/test_audit_multisink.py` (fan-out, per-sink containment,
  `BaseException` propagation, once-per-streak noting, primary-unaffected, syslog Unix +
  UDP delivery, connect- and send-failure containment); the audit module is at 96%.
- BL-103 resolved: a live-PostgreSQL concurrent-create-if-absent regression test
  (`tests/store/test_postgres.py::test_concurrent_create_if_absent_yields_one_winner_and_versionconflict`).
  Two threads, each on its own `PostgresStore` connection, are released together by a
  barrier and both call `put_fact_if(expected_version=None)` for the same key; the test
  asserts exactly one writer wins, the other raises `VersionConflict` (not a raw
  `IntegrityError`), and the loser's transaction rolled back (one active row, history
  length 1). This exercises the create-path CAS contract under genuine contention: the
  create-if-absent case cannot be `FOR UPDATE`-locked, so the partial unique index
  resolves the race and the `IntegrityError` is translated to `VersionConflict`,
  matching the SQLite backend. Gated on `PRAXIS_TEST_PG_DSN` like the rest of the PG
  suite (it import-skips in the default `make check`); the live confirmation runs where
  a Postgres is configured. No production code change.
- BL-033 fully resolved (ADR-0035): a tag-triggered `release` workflow
  (`.github/workflows/release.yml`, `on: push: tags: ['v*']`) publishes the praxis
  container image to GHCR with a Sigstore-signed SLSA provenance attestation and a
  CycloneDX image-SBOM attestation, both bound to the image digest and verifiable with
  one `gh attestation verify oci://...`. It is the sole publisher (PR CI keeps
  build-validating via `image.yml` and never pushes), runs least privilege
  (`packages`/`id-token`/`attestations` write, no `contents: write`), never publishes
  from a fork, uses no moving tags (`flavor: latest=false`; the deploy manifests pin
  the digest, ADR-0001), and pins every action by commit SHA (Renovate-maintained,
  ADR-0033). The pipeline records the digest in its job summary; the operator pins it
  into `values-prod.yaml`/`zarf.yaml` per `deploy/RELEASE-CHECKLIST.md`, so the human
  gate stays on the digest. The all-zero placeholder digest remains the fail-closed
  default until the operator's first tagged release. The workflow is untestable in PR
  CI by construction (tag-triggered); its pins and inputs are reviewed, not CI-proven.
- Opt-in deploy network hardening (ADR-0034; closes BL-036, BL-087), all default off
  so the install posture is unchanged. A `networkPolicy.namespaceDefaultDeny` Helm
  value (default false) renders an additive namespace-wide default-deny NetworkPolicy
  (empty `podSelector`, no allow-rules) so any co-tenant pod without its own policy is
  denied; the praxis pod keeps its allows (policies are additive). A
  `deploy/systemd/praxis.service.d/network-lockdown.conf.example` drop-in carries the
  IP-level lockdown (`IPAddressDeny=any` + an `IPAddressAllow` allowlist +
  `SocketBindDeny=any`) as a turnkey opt-in the operator copies and scopes. The sandbox
  `runtimeClassName` Helm value gains regression tests (absent by default, wired when
  set). Deny-all is never preset because it bricks co-tenant workloads or SSH
  actuation. helm-unittest covers the namespace policy (absent by default, deny-all
  when enabled) and `runtimeClassName`.
- BL-092 (ADR-0032): a repo `Dockerfile` so the deployed image is buildable and
  inspectable from source. Multi-stage, non-root (uid 10001) by construction, on a
  digest-pinned `python:3.12-slim-bookworm` base (distroless ships 3.11, below the
  3.12 floor), installing the default runtime only and running `python -m praxis`.
  Carries governance-as-code OCI labels. A new `image` CI workflow build-validates it
  (build + a non-root import smoke test) and never pushes; publishing the real digest
  is a release step (`deploy/RELEASE-CHECKLIST.md`). Advances BL-033 (the remaining
  element is the real published digest, which needs an actual ghcr publish).
- BL-102 (ADR-0031): an opt-in `health_client_side_only` param on `run_action` for
  the talosctl pre-upgrade health gate. When set it runs `talosctl health
  --server=false` (client-side checks only) so a post-bootstrap cluster whose
  server-side checks spuriously fail can still be upgraded; the default keeps the full
  server-side check. The gate stays HARD and always runs (BL-023); the flag only
  narrows its scope, is coerced fail-closed (a non-boolean is a HARD audited refusal),
  and is recorded in the audited request args. Operator decision per ADR-0021.
- BL-046 fully resolved: the rebinding-aware SSRF egress filter is now wired into a
  live path. The RFC 3161 stamper (BL-095, ADR-0030) is the first server-initiated
  egress consumer; `src/praxis/audit/rfc3161.py::_https_post` resolves and pins through
  `resolve_and_assert_egress_allowed`, and a new regression test
  (`tests/audit/test_rfc3161_tsa.py::test_default_transport_routes_through_the_ssrf_egress_filter`)
  proves the default transport fails closed on a private-range TSA URL before any
  socket. ADR-0025 carries an appended audit note; its first revisit trigger is
  satisfied. No code change beyond the test (the wiring shipped with BL-095).
- Non-forgeable checkpoint stamper (ADR-0029 design, ratified and implemented by
  ADR-0030, BL-095): the evidence layer can now stamp Merkle checkpoints with a real
  RFC 3161 timestamp authority instead of the forgeable keyless `LocalStamper`.
  `Rfc3161Stamper` (`audit/rfc3161.py`) uses `asn1crypto` and `cryptography` behind a
  new optional `tsa` extra, imported lazily so the execution core and the default
  `LocalStamper` stay dependency-free. `stamp` POSTs a DER `TimeStampReq` through the
  BL-046 SSRF egress resolver (its first live consumer; HTTPS, IP-pinned) and `verify`
  is fail-closed, checking the message imprint and verifying the CMS signature against
  the configured TSA certificate. `select_stamper` (config `PRAXIS_TSA_URL` /
  `PRAXIS_TSA_CERT`) is wired into the evidence scheduler and fails closed at startup on
  misconfiguration; `LocalStamper` remains the default and OS append-only storage the
  documented control when no TSA is set (SECURITY.md, ADR-0019). Tested offline with a
  self-signed TSA (round trip plus fail-closed cases); Rekor remains the considered
  alternative behind the same `Stamper` Protocol.
- Governance-hygiene wave (BL-036, partial): three bundle elements delivered.
  `docs/governance/regulatory-deadlines.md` records the EU AI Act, NIS2/NISG, CRA,
  GDPR, and ISO 27001 application/transition dates (ISO 8601), linked from the
  compliance map, so a "planned" control can be tracked against the obligation it
  serves. `deploy/helm/praxis/values-prod.yaml` adds a production overlay that makes
  the hardened posture explicit and marks the operator-supplied values (image digest,
  NetworkPolicy peers and egress) without weakening any default, with
  `deploy/RELEASE-CHECKLIST.md` (the ordered version-bump checklist) and a
  helm-unittest suite asserting the overlay holds the PSA-restricted posture. AGENTS.md
  gains two security-operating hard rules (untrusted collected data and read/act
  separation; never log output bodies). The one remaining BL-036 element, a
  namespace-wide default-deny NetworkPolicy, is deferred for security review rather
  than preset (a deny-all namespace default can brick co-tenant workloads).
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
- Security CI gates are now enforced in-repo (BL-052, ADR-0036). CodeQL and
  dependency-review are folded into the required `ci-success` aggregate as
  reusable-workflow calls, so the single required check transitively requires them
  rather than relying on external branch-protection config (the ruleset required only
  `ci-success`, so the prior "required via branch protection" comment was untrue).
  `fuzz` and `sbom` stay scheduled/publish-only.
- CI now also tests on Python 3.14 (matrix `3.12`/`3.13`/`3.14`); the universal
  hash-locked dev lock already carries cp314 wheels and the full suite passes on 3.14,
  readying the matrix for the upcoming Renovate python base-image bump.
- A `deps-consistency` CI job dry-run-resolves the `dev`+`tsa` extras together to catch
  future `cryptography` bound drift between them (the #57/#62 recurrence); the hashed
  `--no-deps` install path cannot see it.
- Consolidated dependency automation on Renovate (ADR-0033). `renovate.json` is
  replaced by a curated `renovate.json5` (best-practices; the `github-actions`,
  `dockerfile`, and `pip-compile` managers; digest pinning; grouped, scheduled PRs).
  The `requirements-dev.txt` uv header now records the long-form `--output-file` so
  Renovate's pip-compile manager maintains the hash-lock (the short `-o` is rejected
  by its allowlist and was why #55 landed incomplete and needed #57). GitHub's
  Dependabot security-updates are turned off so the two bots no longer raise duplicate
  PRs (the #54/#55 cryptography pair); Dependabot vulnerability *alerts* stay on for
  detection and Renovate raises the fix PRs. A `make lock` target regenerates the
  lock in the required form.
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
- `cryptography` dependency bounds are back in lockstep. The `dev` extra pinned
  `>=46.0.7,<47` while `tsa` (and the committed `requirements-dev.txt` lock) had moved
  to `>=49,<50` after #53, so `pip install .[dev,tsa]` (or any regeneration of the dev
  lock) was unsatisfiable; CI missed it because it installs with `--no-deps`. The `dev`
  bound is aligned to `>=49,<50` (the lock is already at 49.0.0, so it is unchanged).
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
