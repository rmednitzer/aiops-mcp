# Architecture Decision Records

ADRs record standing decisions. Shape: Status, Date, Authors, Context, Decision,
Consequences (positive, negative, neutral), Alternatives considered and rejected,
Revisit triggers. ADRs are immutable: correct factual drift with an appended audit
note, supersede a decision with a new ADR; never rewrite an accepted one.

| ID | Title | Status |
|----|-------|--------|
| [0001](0001-purpose-scope-and-self-contained-monorepo.md) | Purpose, scope, non-goals, and the self-contained monorepo | Accepted |
| 0002 | Self-contained store strategy (StoreProtocol; sqlite default; postgres+age production) | Proposed |
| 0003 | Bitemporal fact model (four timestamps; invalidate-never-delete) | Proposed |
| 0004 | Tiered authority T0-T3 made load-bearing; HITL flows | Proposed |
| 0005 | Execution trust boundary: vendored-and-fused core; scoped credentials; kill switch | Proposed |
| 0006 | MCP transport and auth posture (stdio default; HTTP opt-in invariants; no token passthrough) | Proposed |
| 0007 | Drift engine: desired-state sources and reconciliation | Proposed |
| 0008 | Tamper-evident audit and evidence (hash chain, Merkle, RFC 3161) | Proposed |
| 0009 | STPA/STPA-Sec as the requirements-derivation method | Proposed |
| 0010 | Skills architecture (host-knowledge vs tool skills; registry; eval gate) | Proposed |

ADRs 0002-0010 are seeded as Proposed and are written before the code that
depends on each (build-sequence step 0 in `docs/first-session.md`).
