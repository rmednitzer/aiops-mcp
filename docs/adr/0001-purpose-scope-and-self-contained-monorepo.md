# ADR-0001: Purpose, scope, non-goals, and the self-contained monorepo

| Field   | Value          |
|---------|----------------|
| Status  | Accepted       |
| Date    | 2026-06-07     |
| Authors | Roman Mednitzer |

## Context

A heterogeneous host fleet (mixed Ubuntu releases, Windows, and Talos) is operated
today through a hand-run MCP gateway. That prototype proved the interaction model
but left load-bearing properties un-engineered: graduated autonomy existed only as
a design note, privileged execution was unscoped, drift detection was manual
markdown, state was scattered across markdown and several databases, and skills
were flat files with no router.

The goal is one new product, `praxis` (repository `aiops-mcp`), that fuses the best
patterns from the surrounding estate into a governed, security-first operations
control plane: a live bitemporal model of the fleet, a drift engine, and a tiered
audited actuator, exposed over MCP, operable by a single engineer, suitable for
real production.

## Decision

1. Build `praxis` as a single, self-contained monorepo. It implements everything
   itself and has zero runtime dependency on, and no imports from, any other
   repository. Patterns proven elsewhere are reimplemented natively.
2. Adopt the three-part architecture (bitemporal fleet model, drift engine, tiered
   audited actuator) with strict layering (MCP tools -> skills -> services ->
   store/executor).
3. Treat the nine invariants in `CLAUDE.md` as load-bearing, each backed by a test.
4. Make governance load-bearing from day one: ADRs for decisions, `BL-NNN` backlog
   for work, and STPA/STPA-Sec (`docs/stpa/`) as the source of safety and security
   requirements, mapped to compliance frameworks (EU AI Act, NIS2/NISG, CRA, GDPR,
   ISO 27001).

## Consequences

Positive: one auditable source of truth; no cross-repo coupling or release
coordination; security and governance traceable end to end; portable from a laptop
(SQLite, stdio, no external services) to production.

Negative: more code to own and maintain in-repo (the store, audit integrity, the
executor, the skills engine) rather than depending on existing implementations.

Neutral: the surrounding repositories remain reference material, not dependencies.

## Alternatives considered and rejected

- Build on an existing converged graph store as the backend. Rejected per the
  self-contained requirement; it would couple the control plane to a heavy
  external stack.
- Depend on an existing execution library. Rejected in favor of vendoring and
  fusing the execution core so tiering, audit, and contracts evolve as one unit
  with a single security-review surface.

## Revisit triggers

- The operator set grows beyond one, or the deployment becomes multi-tenant.
- The fleet grows past the point where the SQLite default backend is adequate.
- A decision in ADR-0002 through ADR-0010 conflicts with this scope; in that case
  write a superseding ADR rather than editing this one.
