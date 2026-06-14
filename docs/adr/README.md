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
