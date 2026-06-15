# Architecture Decision Records

ADRs record standing decisions. Shape: Status, Date, Authors, Context, Decision,
Consequences (positive, negative, neutral), Alternatives considered and rejected,
Revisit triggers. ADRs are immutable: correct factual drift with an appended audit
note, supersede a decision with a new ADR; never rewrite an accepted one.

| ID | Title | Status |
|----|-------|--------|
| [0001](0001-purpose-scope-and-self-contained-monorepo.md) | Purpose, scope, non-goals, and the self-contained monorepo | Accepted |
| [0002](0002-self-contained-store-strategy.md) | Self-contained store strategy (StoreProtocol; sqlite default; postgres+age production) | Accepted |
| [0003](0003-bitemporal-fact-model.md) | Bitemporal fact model (four timestamps; invalidate-never-delete) | Accepted |
| [0004](0004-tiered-authority.md) | Tiered authority T0-T3 made load-bearing; HITL flows | Accepted |
| [0005](0005-execution-trust-boundary.md) | Execution trust boundary: vendored-and-fused core; scoped credentials; kill switch | Accepted |
| [0006](0006-mcp-transport-and-auth.md) | MCP transport and auth posture (stdio default; HTTP opt-in invariants; no token passthrough) | Accepted |
| [0007](0007-drift-engine.md) | Drift engine: desired-state sources and reconciliation | Accepted |
| [0008](0008-tamper-evident-audit.md) | Tamper-evident audit and evidence (hash chain, Merkle, RFC 3161) | Accepted |
| [0009](0009-stpa-as-requirements-method.md) | STPA/STPA-Sec as the requirements-derivation method | Accepted |
| [0010](0010-skills-architecture.md) | Skills architecture (host-knowledge vs tool skills; registry; eval gate) | Accepted |
| [0011](0011-external-fleet-audit-2026-06.md) | External fleet-repository audit (2026-06) and validated hardening backlog (BL-017..BL-036) | Accepted |
| [0012](0012-internal-audit-2026-06.md) | Internal deep audit (2026-06) and remediation wave (BL-037..BL-061) | Accepted |
| [0013](0013-actuation-and-input-hardening-2026-06.md) | Third audit wave (2026-06): actuation, audit, and untrusted-input hardening (BL-018/020/021/034/047/048/054/055/057/058/059 resolved; BL-063..BL-068) | Accepted |
| [0014](0014-dependency-posture-and-pydantic.md) | Dependency posture (self-contained = no cross-repo coupling, not anti-PyPI) and pydantic at the external-input boundary (BL-069, BL-070) | Accepted |
| [0015](0015-deep-security-architecture-review-2026-06.md) | Deep security and architecture review (2026-06): approval human-binding, free-form-shell tier floor, latent-control wiring, governance traceability (BL-072..BL-090) | Proposed |
| [0016](0016-approval-hardening-and-enforcement-wave-2026-06.md) | Approval hardening and enforcement wave (2026-06): ratifies ADR-0015 Decisions 3a/3b; minted approval nonces, T2 shell floor, in-path trifecta/budget/kill-switch/broker enforcement, audited reads and ingest (BL-017/019/022..026/029/049/056/062/068/072..085/090 resolved) | Accepted |
| [0017](0017-full-audit-pass-2026-06-12.md) | Full audit, validation, and hardening pass (2026-06-12): re-validated baseline and evidence under `audit/`; no critical/high/medium findings; files BL-091..BL-093 (Postgres `seq` residual, missing Dockerfile, Helm transport default); no code change | Accepted |
| [0018](0018-backlog-remediation-wave-2026-06-12.md) | Backlog remediation wave (2026-06-12): Postgres seq-race and TRUNCATE storage-layer parity (live-verified), hash-locked CI installs and bounded toolchain, coverage floor on ci-success, fail-closed Helm ingress and secret-ref DSN, audit entry-hash self-consistency (BL-028/051/053/086/088/091/093/094 resolved) | Accepted |
| [0019](0019-runtime-evidence-and-anchor-2026-06-12.md) | Runtime evidence production and the anchored high-water mark (2026-06-12): the server checkpoints the audit log every N records and at shutdown; optional anchor file detects truncation of log plus evidence together; snapshot hashes Merkle-committed by composition (BL-030/050/076 resolved; BL-095 filed for the non-forgeable stamper) | Accepted |
| [0020](0020-test-and-deploy-hardening-wave-2026-06-12.md) | Test/fuzz expansion and deploy hardening (2026-06-12): SSRF bypass sweep (6to4 relay anycast blocked), adapter x host_type refusal matrix, SQLite/Postgres parity suite, fuzz manifest/merkle/evidence stages, systemd PrivateUsers/ProcSubset/RemoveIPC, scoped Helm NetworkPolicy egress (BL-061/096 resolved; BL-087 advanced) | Accepted |
| [0021](0021-cross-fleet-pattern-integration-wave-2026-06-13.md) | Cross-fleet pattern integration wave (2026-06-13): machine-checkable compliance catalog + bidirectional validator gated in CI, provider/MySQL redaction hardening, additive Talos partition-scoped reset, content-hash compare-and-set for supersede (BL-027/031/097/098 resolved; BL-036 advanced; CIS baseline, multi-sink, audit correlation, client-side health probe filed) | Accepted |
| [0022](0022-stpa-traceability-completion-2026-06-14.md) | STPA traceability completion (2026-06-14): every UCA-1..28 mapped to a covering SEC "Prevents" column, mode-ceiling escalation (UCA-23) covered under SEC-3 with a proving test, planned `act_redfish`/`act_cloud` UCAs pre-staged and flagged (BL-089 resolved) | Accepted |
| [0023](0023-audit-evidence-retention-tiers-2026-06-14.md) | Audit and evidence retention tiers (2026-06-14): `PRAXIS_AUDIT_RETENTION_DAYS`/`PRAXIS_EVIDENCE_RETENTION_DAYS` bound in config (default 365, 0=indefinite), bound into the session record, enforced by storage-layer archival because the trail is append-only (NIS2 Art. 23, ISO 27001 A.8.15; implements ADR-0011 finding 035 / BL-035) | Accepted |
| [0024](0024-cis-talos-fact-predicate-schema-2026-06-14.md) | CIS-Talos drift baseline: the fact-predicate schema (2026-06-14): `KNOWN_GOOD` facts keyed `host:<name>`/`cluster:<name>` + `cis:<benchmark>:<control_id>`, comparable `value` vs documentation in `reason`, CIS-aware severity via the existing `severity_for` hook, explicit `CIS_SUPPRESSED`/`TALOS_SATISFIED` sets; no engine change (prerequisite decision for BL-099) | Proposed |
| [0025](0025-ssrf-rebinding-aware-resolution-2026-06-14.md) | Rebinding-aware SSRF egress resolution (2026-06-14): additive `resolve_and_assert_egress_allowed` that resolves a host, checks every resolved IP, and returns the vetted IPs to pin the connection; strict deny-names default unchanged; the RFC 3161 stamper (ADR-0030) is its first egress consumer, so the BL-046 resolver and wiring are both delivered (BL-046 resolved; appended audit note) | Accepted |
| [0026](0026-deploy-config-cleanup-2026-06-14.md) | Deploy and config cleanup; Helm health probes (2026-06-14): configurable `tcpSocket` liveness/readiness probes on the MCP port, rendered only for the http transport (verified with helm); compliance-map path-citation convention; records the BL-067/071/087 sub-items already closed (closes BL-060) | Accepted |
| [0027](0027-helm-chart-unit-tests-2026-06-14.md) | Helm chart unit tests gated in CI (2026-06-14): helm-unittest suites asserting the PSA-restricted securityContext, digest pinning, secret-ref-only wiring, http-gated probes, and the default-deny NetworkPolicy; a pinned `helm-test` job folded into the required `ci-success` aggregate; `make helm-test` for local parity (closes BL-032) | Accepted |
| [0028](0028-cis-talos-baseline-implementation-2026-06-14.md) | CIS-Talos drift baseline implementation (2026-06-14): ratifies ADR-0024 and implements BL-099; the vetted `CIS_BASELINE` plus `normalize_value`, `cis_severity`, `cis_baseline_facts`, `cis_drift`, `seed_cis_baseline`, the read-only `CisCollector` wired into `ingest_observation`, and CIS-aware severity in `drift_scan`; no engine change, no new tool/UCA (closes BL-099) | Accepted |
| [0029](0029-non-forgeable-checkpoint-stamper-2026-06-14.md) | Non-forgeable checkpoint stamper: RFC 3161 timestamp authority (2026-06-14): proposes replacing the forgeable `LocalStamper` with a real `Rfc3161Stamper` behind an optional `tsa` extra (`asn1crypto` + `cryptography`), egress via the BL-046 resolver, fail-closed offline-verifiable tokens; `LocalStamper` stays the default; recorded Proposed for ratification before implementation (design decision for BL-095) | Proposed |
| [0030](0030-rfc3161-stamper-implementation-2026-06-14.md) | RFC 3161 stamper implementation (2026-06-14): ratifies ADR-0029 and implements BL-095; the real `Rfc3161Stamper` (asn1crypto + cryptography behind the `tsa` extra), SSRF-pinned egress via the BL-046 resolver, fail-closed CMS verification against a configured TSA certificate, `select_stamper` wired into the evidence scheduler; `LocalStamper` stays the default and the core dependency-free (closes BL-095) | Accepted |
| [0031](0031-talosctl-client-side-health-probe-2026-06-14.md) | Opt-in client-side-only talosctl pre-upgrade health probe (2026-06-14): implements BL-102 (the operator decision deferred by ADR-0021); an additive `health_client_side_only` param runs `talosctl health --server=false` so a post-bootstrap cluster's spurious server-side checks cannot block an upgrade; the HARD gate (BL-023, SEC-5) still always runs, the default keeps the full check, and a non-boolean flag is a fail-closed HARD refusal | Accepted |
| [0032](0032-container-image-build-2026-06-14.md) | Container image build (2026-06-14): implements BL-092 and advances BL-033; a multi-stage, non-root, digest-pinned (`python:3.12-slim-bookworm`) `Dockerfile` that installs the default runtime and runs `python -m praxis`, with governance-as-code OCI labels, build-validated by a new `image` CI workflow (never pushed); the published digest stays a release step (the remaining BL-033 element) | Accepted |
| [0033](0033-consolidate-dependency-automation-on-renovate.md) | Consolidate dependency automation on Renovate (2026-06-14): curated `renovate.json5` (github-actions + dockerfile + pip-compile managers, digest pinning, grouped/scheduled PRs), the uv lock header normalised to `--output-file` so the pip-compile manager maintains it, and Dependabot security-updates turned off so the two bots stop raising duplicate PRs (#54/#55); Dependabot vulnerability alerts kept for detection | Accepted |
| [0034](0034-opt-in-deploy-network-hardening-2026-06-14.md) | Opt-in deploy network hardening (2026-06-14): closes the BL-036 namespace-NetworkPolicy element and the BL-087 residual as turnkey opt-ins, all default off so the install posture is unchanged; a `networkPolicy.namespaceDefaultDeny` Helm value renders an additive deny-every-pod baseline, a `network-lockdown.conf.example` systemd drop-in carries the `IPAddressDeny`/`SocketBindDeny` lockdown, and `runtimeClassName` stays the optional value (now tested); deny-all is never preset because it bricks co-tenants/actuation | Accepted |
| [0035](0035-release-publish-pipeline-2026-06-14.md) | Release publish pipeline with signed provenance and SBOM attestation (2026-06-14): closes the remaining BL-033 element; a tag-triggered (`v*`) `release` workflow is the sole publisher (PR CI never pushes), builds and pushes a plain single-arch image to GHCR, and binds a Sigstore-signed SLSA provenance and a CycloneDX SBOM attestation to the digest (`gh attestation verify`-able); least privilege (no `contents: write`), no moving tags, all actions SHA-pinned; the operator pins the recorded digest per RELEASE-CHECKLIST (the human gate stays on the digest) | Accepted |
| [0036](0036-required-security-gates-in-ci-2026-06-14.md) | Required security gates folded into the ci-success aggregate (2026-06-14): CodeQL and dependency-review become reusable-workflow calls invoked by `ci.yml` so the single required `ci-success` check transitively requires them in-repo (not via external branch protection); `if: always()` + a per-gate result check tolerates legitimate skips; fuzz/sbom stay scheduled/publish (BL-052) | Accepted |
| [0037](0037-multi-sink-audit-fanout-2026-06-14.md) | Multi-sink audit fan-out with per-sink containment (2026-06-14): closes BL-100 by adding a second audit sink (`SyslogAuditSink`, opt-in `PRAXIS_AUDIT_SYSLOG_ADDRESS`, default off) and a `MultiSink` (the `skills/dispatch` fan-out class applied to the audit write side) that contains a per-sink `Exception` so one failing sink cannot silence the others, while `BaseException` propagates; the append-only hash-chained file stays authoritative (written first, directly) and secondaries are best-effort forwards fanned out after it | Accepted |
| [0038](0038-audit-request-client-correlation-2026-06-14.md) | Audit request/client correlation identifiers (2026-06-14): closes BL-101 with two optional, additive audit fields (`request_id`, `client_id`, inside the hashed payload) threaded ambiently via `contextvars` (`request_scope` set by the transport, read by `run`), so concurrent calls correlate to their entries without timestamp matching and no tool signature changes; the stdio transport binds the JSON-RPC request id, `client_id` awaits a multi-client transport (HTTP, BL-012), and the client-supplied id is length-bounded so it cannot bloat a record | Accepted |
| [0039](0039-second-full-audit-pass-2026-06-14.md) | Second full audit, validation, and adversarial-testing pass (2026-06-14): re-validates the merged tree (`209f61a` plus #69 and #71) after the 0018..0038 waves with fresh command-backed evidence (all gates green, 92% coverage, pip-audit clean, fuzz 200k clean) and an executed adversarial battery (5/5 controls held); confirms every 2026-06-12 finding (BL-091/092/093, BL-088 items) closed and reviews the #69/#71 audit deltas; files one Info/latent item (BL-104) for the future multi-client HTTP transport; no code change | Accepted |
| [0040](0040-deep-audit-2026-06-14.md) | Deep audit, validation, and adversarial-testing pass (2026-06-14): a parallel deeper pass alongside ADR-0039; re-validates the nine invariants and STPA traceability (no critical/high findings; compliance validator 0 violations) and remediates six findings in-pass with tests (F-001 audit `_canonical` never-raises; F-006 Anthropic/HF/DigitalOcean redaction; F-007 supersede rowcount race; F-004 `rm -rf //`/`/*` deny; F-008 Talos non-JSON cap; F-003 OpenTofu unconfined `chdir`); documents F-002/F-005/F-009; files BL-105..109; records the pass under `audit/2026-06-14/` | Accepted |
| [0041](0041-multi-client-http-transport-2026-06-14.md) | Multi-client HTTP transport (2026-06-14): builds the staged HTTP serving loop (BL-012) on stdlib `http.server` with an `Mcp-Session-Id` session lifecycle; per-session isolation of the trifecta taint latch and a lock-guarded atomic approval registry (BL-104), constant-time bearer-token auth (BL-106), a request-body cap (BL-107), and the per-client consent ceiling (ADR-0006 Decision 4); single-threaded in v1 (concurrent serving over a thread-safe store is BL-110) | Accepted |
| [0042](0042-concurrent-http-serving-2026-06-15.md) | Concurrent HTTP serving (2026-06-15): the ADR-0041 follow-up (BL-110). Serialises every store method on a per-instance `RLock` (`synchronized` in `store/base.py`; SQLite `check_same_thread=False`), makes `BudgetTracker` check-and-charge atomic, and switches to `ThreadingHTTPServer` (`daemon_threads`), so a slow actuation no longer blocks other clients while the bitemporal/append-only invariants hold; taint latch and kill switch stay lock-free (monotonic, fail-safe) | Accepted |
| [0043](0043-kubernetes-actuation-credential-contract-2026-06-15.md) | Kubernetes actuation credential contract (2026-06-15): a first-class `kubectl`/`helm` adapter is admissible only under a scoped-static-kubeconfig contract (RBAC-scoped, non-admin kubeconfig referenced out of band via the already-allowlisted `KUBECONFIG`; a new `HostType.KUBERNETES` carrying kubeconfig path + context pinned from trusted inventory; `confine_to_root` paths; `exec`-stanza kubeconfigs refused fail-closed; verb allowlist; native `--dry-run`; SEC-5/6/8 mapping; pre-staged `act_kubectl`/`act_helm` UCAs). Otherwise Kubernetes/Helm stays a bastion-host skill. ArgoCD kept out of actuation (overlaps the drift engine, ADR-0007). Builds nothing; default posture and dependency set unchanged (files BL-111) | Proposed |

ADRs 0002-0010 were written governance-first, before the code that depends on each,
and accepted as the basis for that code.
ADR-0011 is a post-hoc audit wave: it records cross-fleet findings, each validated
against a trusted source, accepted as a hardening backlog (not yet implemented).
ADR-0012 and ADR-0013 are internal audit waves that remediate a reproduced cluster
of findings in the accompanying change (each fix carries a regression test) and
leave the architectural items tracked and open. ADR-0014 clarifies the dependency
posture (an appended audit note on the immutable ADR-0001) and adopts pydantic at the
external-input boundary.
ADR-0015 is a deep review wave recorded with Status Proposed: it enumerates findings
as BL-072..BL-090 and proposes two architectural refinements (a human-binding
approval gate and a tier floor for free-form shell actuation) for ratification before
implementation.
ADR-0016 ratifies both ADR-0015 proposals and implements them, with the enforcement
wave that wires the latent controls and routes every tool through the audited path;
each resolved finding carries a regression test in the accompanying change.
ADR-0017 through ADR-0020 are audit, remediation, evidence, and hardening waves.
ADR-0021 is a pattern-integration wave: it adopts four self-contained, proven
fleet-operations patterns natively (a machine-checkable compliance catalog with a
CI-gated bidirectional validator, redaction hardening, an additive Talos
partition-scoped reset, and content-hash compare-and-set for supersede), each with a
regression test, and files the larger findings as tracked backlog items.
ADR-0022 is a governance-traceability completion: it resolves the last ADR-0015
finding (BL-089) by mapping every UCA to a covering SEC constraint, covering the
mode-ceiling escalation (UCA-23) under SEC-3 with a proving test, and pre-staging the
planned-adapter UCAs; it documents existing enforcement rather than changing runtime
behavior.
ADR-0023 implements ADR-0011 finding 035 (BL-035): audit and evidence retention
tiers bound in config and into the session audit record, enforced by storage-layer
archival because the trail is append-only (no runtime deletion path), mapped to NIS2
Art. 23 and ISO 27001 A.8.15.
ADR-0024 is the prerequisite schema decision for BL-099 (recorded Proposed for
ratification before implementation; ratified and implemented by ADR-0028): it fixes
how CIS Kubernetes/Talos controls are named as `(subject, predicate, fact_type)`
facts, the comparable-`value` versus documentation-`reason` split that keeps the
equality diff reliable, CIS-aware severity through the existing `severity_for` hook,
and an explicit, documented suppression and Talos-satisfied policy. It changes no code.
ADR-0025 adds the rebinding-aware SSRF egress primitive
(`resolve_and_assert_egress_allowed`): it resolves a host, checks every resolved
address, and returns the vetted IPs so a caller pins the connection, additively
beside the unchanged strict deny-names default. It resolves BL-046's resolution half;
the wiring into a live egress path landed with the RFC 3161 stamper (ADR-0030), its
first egress consumer, which resolves and pins through the helper, closing BL-046.
ADR-0026 closes the BL-060 deploy/config residuals: configurable `tcpSocket`
liveness/readiness probes on the Helm chart (rendered only for the http transport,
verified with helm) and a compliance-map path-citation convention, recording that the
HTTP_HOST strip, the cyclonedx pin, and the systemd de-duplication were already closed
in earlier waves.
ADR-0027 closes BL-032: helm-unittest suites assert the chart's load-bearing posture
(PSA-restricted `securityContext`, digest pinning, secret-ref-only secret wiring, the
http-gated health probes from ADR-0026, and the default-deny NetworkPolicy), gated by
a pinned `helm-test` job folded into the required `ci-success` aggregate so it is
required without a new branch-protection rule, with a `make helm-test` target for
local parity. It adds a CI/dev dependency only and leaves the execution core
dependency-free posture (ADR-0014) untouched.
ADR-0028 ratifies ADR-0024 and implements BL-099: the CIS-Talos desired-state baseline
as drift data. It adds `drift/cis.py` (the vetted baseline, one symmetric
normalization, the `cis_severity` hook, the suppression and Talos-satisfied policy, and
the materialization, diff, and seed helpers) and a read-only `CisCollector`, wiring CIS
through the existing audited surface (the collector via `ingest_observation`, CIS-aware
severity in `drift_scan`) with no engine change and no new tool or UCA. ADR-0024 stays
the schema of record (Proposed, with a ratification note); ADR-0028 carries the
accepted implementation, the parallel to how ADR-0016 ratified ADR-0015.
ADR-0029 is the design decision for BL-095 (recorded Proposed for ratification before
implementation; ratified and implemented by ADR-0030): it proposes replacing the
forgeable keyless `LocalStamper` with a real RFC 3161 timestamp-authority `Stamper`
behind an optional `tsa` extra (`asn1crypto` + `cryptography`), POSTing a DER
`TimeStampReq` through the BL-046 SSRF egress resolver and storing an offline-verifiable,
fail-closed token; `LocalStamper` stays the default and the core stays dependency-free.
It is recorded Proposed because it adds a third-party dependency (an ADR-0014 posture
decision) and chooses RFC 3161 over a Rekor transparency-log anchor.
ADR-0030 ratifies ADR-0029 and implements BL-095: the real `Rfc3161Stamper` using
`asn1crypto` (TSP/CMS models) and `cryptography` (signature/certificate verification)
behind the `tsa` extra, with the extra's libraries imported lazily so the core and the
default `LocalStamper` stay dependency-free. `stamp` POSTs a DER `TimeStampReq` through
the BL-046 SSRF-pinned egress (its first live consumer) and `verify` is fail-closed,
checking the imprint and verifying the CMS signature against a configured TSA
certificate; `select_stamper` is wired into the evidence scheduler and fails closed on
misconfiguration. The whole path is unit-tested offline with a self-signed TSA. ADR-0029
stays the design of record (Proposed, with a ratification note); ADR-0030 carries the
accepted implementation, the parallel to how ADR-0028 implemented ADR-0024.
ADR-0031 takes the operator decision ADR-0021 deferred as BL-102: an additive,
opt-in `health_client_side_only` param narrows the HARD pre-upgrade `talosctl health`
gate (BL-023, SEC-5) to `--server=false` (client-side checks only), for a
post-bootstrap cluster whose server-side checks spuriously block an upgrade. The gate
still always runs and stays HARD; the default keeps the full server-side check; a
non-boolean flag is coerced fail-closed into a HARD audited refusal. The capability is
audited (a structured `run_action` param) and never weakens the default.
ADR-0032 implements BL-092 and advances BL-033: a multi-stage, non-root,
digest-pinned `Dockerfile` makes the deployed image buildable and inspectable from
source (the runtime stage runs `python -m praxis` as a fixed non-root uid on a
digest-pinned `python:3.12-slim-bookworm` base; distroless is rejected for shipping
Python 3.11). It carries governance-as-code OCI labels and is build-validated by a new
`image` CI workflow that never pushes; the real published digest stays a release-time
step, the remaining BL-033 element.

ADR-0033 consolidates dependency automation on Renovate: it replaces the bare
`renovate.json` with a curated `renovate.json5` (the `github-actions`, `dockerfile`, and
`pip-compile` managers, digest pinning, grouped and scheduled PRs), normalises the `uv`
lock header to the long-form `--output-file` so Renovate's `pip-compile` manager
maintains the hashed `requirements-dev.txt`, and turns off GitHub's Dependabot
security-updates so the two bots stop raising the duplicate PRs seen in the #54/#55
cryptography pair. Dependabot vulnerability alerts stay on for detection and Renovate
raises the fix PRs.
ADR-0034 closes the two deferred deploy-network controls as turnkey opt-ins, all
default off so the install posture is unchanged: `networkPolicy.namespaceDefaultDeny`
renders an additive namespace-wide deny-every-pod baseline (BL-036), a
`network-lockdown.conf.example` systemd drop-in carries the IP-level
`IPAddressDeny`/`SocketBindDeny` lockdown, and the sandbox `runtimeClassName` stays the
optional Helm value, now with regression tests (BL-087). Deny-all is never preset
because it bricks co-tenant workloads or SSH actuation; the operator opts in.
ADR-0035 closes the remaining BL-033 element (the published, attested digest) by
satisfying ADR-0032's revisit trigger: a tag-triggered (`v*`) `release` workflow is the
sole publisher (PR CI keeps build-validating and never pushes), builds and pushes a
plain single-arch image to GHCR with no moving tags, and binds a Sigstore-signed SLSA
provenance attestation and a CycloneDX SBOM attestation to the image digest
(`push-to-registry`, verifiable with one `gh attestation verify`). It runs least
privilege (`packages`/`id-token`/`attestations` write, no `contents: write`), never
publishes from a fork, and pins every action by commit SHA. The pipeline records the
digest in its job summary; the operator pins it into the deploy manifests per
RELEASE-CHECKLIST, so the human gate stays on the digest. The all-zero placeholder
remains the fail-closed default until the operator's first release.

ADR-0036 folds the pull-request security gates (CodeQL, dependency-review) into the required `ci-success` aggregate as reusable-workflow calls, so enforcement lives in the repository's CI graph rather than in mutable branch-protection config; `fuzz` and `sbom` stay scheduled/publish-only (BL-052).
ADR-0037 closes BL-100 by making the audit log multi-sink. It adds a second sink
(`SyslogAuditSink`, a best-effort forward of each redacted line to syslog, opt-in via
`PRAXIS_AUDIT_SYSLOG_ADDRESS`, default off) and a `MultiSink` that applies the
`skills/dispatch` fan-out class to the audit write side: a per-sink `Exception` is
contained (noted once per streak) so one failing sink cannot silence the others, while
`BaseException` propagates and `emit` never raises. The append-only hash-chained file
stays authoritative, written first and directly; secondary sinks are fanned out after
it, so no best-effort sink can affect the primary write, the chain, or `verify_chain`.
ADR-0038 closes BL-101 by adding optional request/client correlation to the audit
record. `AuditRecord` and `record` gain `request_id` and `client_id` (inside the hashed
payload, so tamper-evident); they are threaded ambiently via `contextvars`
(`execution/correlation.py`: `request_scope` set by the transport, read by `run`), so no
tool signature changes. The stdio transport binds the JSON-RPC request id; `client_id`
stays `None` until a multi-client transport (HTTP, BL-012) sets it. The client-supplied
id is coerced and truncated to `MAX_ID_LEN` and never raises, so a hostile client cannot
bloat a record (SEC-9, invariant 3).
ADR-0039 records the second full-pass audit (2026-06-14): a read-only re-validation of the merged tree (`209f61a` plus #69 and #71) after the 0018..0038 waves. It confirms the first pass's findings (ADR-0017: BL-091/092/093 and the BL-088 items) are all closed, re-runs the gate suite, the fuzzer, and an executed adversarial battery (SSRF, redaction, deny-first policy, approval forgery/replay, audit-chain tamper -- 5/5 held), reviews the #69 multi-sink and #71 correlation deltas (both preserve the audit invariants), and finds no Critical/High/Medium/Low issues. The one Info/latent observation -- the process-global `ExecutionContext`/`ApprovalRegistry` that becomes load-bearing only under a multi-client HTTP transport -- is filed as BL-104. The `audit/` evidence files are refreshed in place (the living regression reference); ADR-0017 remains the 2026-06-12 historical record.
ADR-0040 is a parallel, deeper deep-audit pass (2026-06-14) alongside ADR-0039: a re-validation of the nine invariants and STPA traceability (no critical/high findings) plus adversarial testing that additionally remediates six findings in-pass, each with a regression test (audit `_canonical` never-raises; redaction of Anthropic/HuggingFace/DigitalOcean tokens; the supersede rowcount race on both store backends; the `rm -rf //` / `/*` deny miss; the Talos non-JSON cap; the OpenTofu unconfined `chdir`), documents three accepted dispositions (F-002 pattern-based redaction, F-005 operator-trusted syslog destination, F-009 ADR-0015 ratification note), and files BL-105..109 for deferred hardening. The pass is recorded under `audit/2026-06-14/`.
ADR-0041 builds the multi-client HTTP transport (BL-012), the serving loop that was staged behind the always-enforced ADR-0006 guard. Stdlib `http.server` only (no web framework); `initialize` mints an `Mcp-Session-Id` and a per-session `ServerContext` that shares the global audit chain, store, and kill switch but has its own trifecta taint latch, approval registry, budget, and consent ceiling, so one client cannot taint another or race another's approval (BL-104). Every request carries a bearer token compared in constant time (BL-106) and a capped body (BL-107); a session may declare a consent ceiling that denies above-ceiling actions in the audited path (ADR-0006 Decision 4 / BL-045). Single-threaded in v1 (concurrent serving over a thread-safe store is BL-110).

ADR-0042 closes that follow-up (BL-110). It serialises every store method on a per-instance
re-entrant lock (a `synchronized` decorator in `store/base.py`, applied to both `SqliteStore`
and `PostgresStore`; SQLite is opened `check_same_thread=False`), makes the `BudgetTracker`
check-and-charge atomic, and switches the transport to `ThreadingHTTPServer` with
`daemon_threads`, so requests run in parallel and a slow actuation no longer blocks other
clients. The audit hash chain and the evidence scheduler were already lock-guarded, and
per-session isolation is unchanged, so every bitemporal/append-only invariant holds; the
taint latch and kill switch stay lock-free because both are monotonic and fail-safe. A
universal locking proxy was rejected (it would let a backend fake unsupported capabilities);
per-thread connections were rejected for v1 (the `:memory:` default is per-connection).
