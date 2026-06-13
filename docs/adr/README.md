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
