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

ADRs 0002-0010 were written before the code that depends on each (build-sequence
step 0 in `docs/first-session.md`) and accepted as the basis for that code.
ADR-0011 is a post-hoc audit wave: it records cross-fleet findings, each validated
against a trusted source, accepted as a hardening backlog (not yet implemented).
