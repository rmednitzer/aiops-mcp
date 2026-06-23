# ADR-0044: Distillation and external-source validation pass (2026-06-23)

## Status

Accepted

## Date

2026-06-23

## Authors

praxis maintainers

## Context

A periodic distillation pass: re-derive what praxis is from the code and the
governance spine, then validate the load-bearing external claims against their
trusted sources, and bring the prose current. It follows the audit passes in
ADR-0039 and ADR-0040 and uses the same idiom (a recorded pass, findings with
dispositions, prose-drift corrections). This pass is documentation and validation
only: no code behaviour changes.

Method:

- Re-read the distillation surfaces (`README.md`, `docs/architecture.md`,
  `AGENTS.md`, `CLAUDE.md`, `docs/index.md`) and confirmed they still describe the
  built system.
- Verified the documented structural claims against the code: six registered MCP
  tools (`query_facts`, `fact_history`, `ingest_observation`, `drift_scan`,
  `run_action`, `emergency_stop`); the four-member `HostType` enum; `PATTERNS_VERSION`
  4; the nine invariants each with a proving test. `make ci-success` is green at
  92% coverage (ruff + mypy strict + pytest + schema-drift + eval + compliance +
  coverage).
- Validated the load-bearing external claims against the trusted sources named in
  `docs/architecture.md` ("Trusted external sources").

## Decision

Record the validation matrix and the one substantive finding, and bring the prose
current.

External-source validation matrix:

| Claim (where) | Trusted source | Result |
|---------------|----------------|--------|
| MCP protocol version `2025-11-25` (`server.py`, `docs/guide.md`, roadmap) | modelcontextprotocol.io specification | Current: 2025-11-25 is the latest stable revision (released on the protocol's one-year anniversary). The dated stable spec URLs are live; the roadmap references were moved from the rolling `/draft/` path to the dated `2025-11-25` path. |
| RFC 6962 Merkle domain separation (`audit/merkle.py`) | RFC 6962 | Correct: empty root is `SHA-256("")`, leaf is `SHA-256(0x00 \|\| d)`, node is `SHA-256(0x01 \|\| l \|\| r)`, split at the largest power of two below `n`. Reproducible by any compliant verifier. |
| CRA dates (`docs/governance/regulatory-deadlines.md`) | EU Commission CRA reporting guidance | Current: reporting obligations apply 2026-09-11 (Single Reporting Platform operational by that date), main obligations 2027-12-11. No drift. |
| EU AI Act high-risk application dates (`docs/governance/regulatory-deadlines.md`) | Council/Parliament Digital Omnibus on AI | Drift found and corrected (see below). |

Finding (Documentation, Low): the AI Act high-risk application dates had drifted.
The Digital Omnibus on AI, a targeted amendment package to Regulation (EU) 2024/1689,
reached a provisional co-legislator agreement on 2026-05-07 that defers the high-risk
obligations: Annex III stand-alone systems from 2026-08-02 to 2027-12-02 (16 months),
and Annex I product-embedded systems from 2027-08-02 to 2028-08-02 (12 months). The
package also adds two Art. 5 prohibited practices (AI-generated non-consensual intimate
imagery and CSAM); praxis defines no such system, so its prohibited-practice disposition
is unchanged. As of this pass the package is politically agreed but not yet formally
adopted or published in the Official Journal (formal adoption is expected before the
2026-08-02 statutory date it supersedes). `regulatory-deadlines.md` now carries the
deferred dates inline (marked `deferred; statutory date was ...`) plus a note that the
deferral is provisional and the original dates remain in force until the OJ publishes.
The re-confirmation against the OJ is filed as BL-113.

Internal consistency was re-confirmed: the ADR index and the hard-coded counts in the
docs matched the code, with the ADR count and the `mkdocs.yml` comment advanced to 44
for this ADR. The backlog held 111 resolved items with BL-111 the only open one before
this pass; this pass files BL-113 (the AI Act re-confirmation), so two items are now
open, and the README status blurb is updated to name both. One pre-existing
documentation gap was closed in the same pass: `PRAXIS_ALLOW_RESTRICTED` (read by
`config.py`, default `true` on stdio and `false` over HTTP, gating whether
restricted-classification tool output is returned) was undocumented; it is added to the
configuration table in `docs/guide.md`.

## Consequences

Positive: the governance prose is current against the Official Journal position as of
2026-06; the spine and the external claims are validated and the matrix is recorded for
the next pass; the one drifted date is corrected without overstating a provisional
amendment as settled law.

Negative: BL-113 stays open until the Digital Omnibus publishes in the Official Journal;
the deferred dates are provisional until then.

Neutral: no code change; the ADR count is 44; the trusted-source matrix above is the
template for the next periodic distillation pass.

## Alternatives considered and rejected

- Overwrite the statutory AI Act dates with the deferred dates as settled law. Rejected:
  the Digital Omnibus is provisional and not yet in the Official Journal; presenting it as
  final would misstate the in-force obligations.
- Leave `regulatory-deadlines.md` unchanged and note the deferral only in the changelog.
  Rejected: the file is the operational deadline reference, and a stale 2026-08-02 date
  becomes actively misleading as that date approaches.
- Create a standalone distillation document. Rejected: `README.md`, `docs/architecture.md`,
  and `AGENTS.md` already distil the system at three altitudes; recording the pass as an
  ADR matches the project idiom (ADR-0039/0040) and avoids a new surface to keep current.

## Revisit triggers

- The Digital Omnibus on AI is formally adopted and published in the Official Journal:
  re-confirm the high-risk dates and the in-force status, and close BL-113.
- A new MCP specification revision supersedes 2025-11-25: re-validate `MCP_PROTOCOL_VERSION`
  and the spec URLs.
- The next periodic deep-audit or distillation pass.
