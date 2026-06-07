# aiops-mcp

**praxis**, the unified AI-operations MCP.

> Status: bootstrapping. This repository was scaffolded governance-first. The
> implementation is built by following `docs/first-session.md` (the build brief).

## What it is

`praxis` is a self-contained, security-first, single-operator-operable,
EU-sovereign **unified AI-operations MCP server**. It fuses three things into one
control plane:

1. **A live bitemporal model of the fleet.** Hosts, services, packages, storage,
   networks, identities, and alerts as typed vertices and edges, with every fact
   carrying four timestamps and never being deleted (corrections supersede). The
   source of truth.
2. **A drift engine.** Observed host state vs desired state (IaC plan, config
   baseline, or an operator-blessed known-good snapshot), with structured drift
   findings and human-gated convergence.
3. **A tiered, audited actuator.** A single execution path that classifies every
   action T0-T3, gates state-changing actions behind human confirmation, and wraps
   the right tool per host type (ssh/ansible/opentofu/runbooks/talosctl/redfish/
   cloud) instead of reinventing it.

It implements everything itself. It has zero runtime dependency on, and no
imports from, any other repository.

## Why

It is the engineered successor to a hand-run fleet gateway: graduated autonomy
made load-bearing in code (not just a design note), drift detection formalized out
of manual markdown baselines into a queryable bitemporal store, scattered state
unified, and flat skills given a real registry and router. Security-first, for
real production deployments.

## Quickstart (for the first build session)

Open a Claude Code session in this repository and follow `docs/first-session.md`.
It is self-sufficient and lays out the nine non-negotiable invariants, the
architecture, the layout, and an ordered build sequence.

## Layout

See `docs/first-session.md` for the full tree. The spine: `src/praxis/execution/`
(the single audited executor), `src/praxis/store/` (the pluggable bitemporal
store), `src/praxis/drift/` (the drift engine), `src/praxis/actuation/` (tool
adapters), `src/praxis/tools/` (the MCP surface), and `docs/{adr,stpa}/` plus
`docs/backlog.md` (governance-as-code).

## Governance

- Decisions: `docs/adr/` (Architecture Decision Records).
- Safety and security requirements: `docs/stpa/` (System-Theoretic Process
  Analysis, including STPA-Sec).
- Work tracking: `docs/backlog.md` (stable `BL-NNN` ids).
- Compliance mapping: `docs/governance/` (EU AI Act, NIS2/NISG, CRA, GDPR, ISO
  27001).

## License

Apache-2.0 (see `LICENSE`; full text added as `BL-001` in the first build session)
and `NOTICE`.
