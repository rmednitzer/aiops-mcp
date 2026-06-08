# aiops-mcp

**praxis**, the unified AI-operations MCP.

> Status: v0, stdio only, single-operator, in iterative security hardening.
> `make ci-success` is green (ruff + mypy strict + pytest + the schema-drift guard
> + the dispatch eval gate) and each of the nine invariants has a passing test, but
> a deep review (ADR-0015) found that several controls the design treats as
> load-bearing are specified and partly built yet not fully wired into the running
> server. Read "Maturity and honest limitations" below and `LIMITATIONS.md` before
> relying on it. Audit waves: ADR-0011 through ADR-0015; open work is in
> `docs/backlog.md`. The design reference is `docs/architecture.md`.

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

It is self-contained: no imports from, or runtime coupling to, any sibling fleet
repository. Third-party libraries are kept minimal and license-vetted (pydantic for
input validation; psycopg for the optional Postgres backend), and the execution core
stays dependency-free (ADR-0001, ADR-0014).

## Why

It is the engineered successor to a hand-run fleet gateway: graduated autonomy
being made load-bearing in code (not just a design note), drift detection
formalized out of manual markdown baselines into a queryable bitemporal store,
scattered state unified, and flat skills given a real registry and router.
Security-first by design and intended for real production deployments, with the
gaps still on the way to that bar tracked openly (see below).

## Maturity and honest limitations

v0 is real and tested, but it is a hardening-in-progress security project, not a
finished product. The deep review in ADR-0015 (2026-06-08) verified the spine is
sound (storage-layer append-only state, parameterised SQL, inert untrusted skill
bundles, an option-injection-guarded SSH target, an RFC 6962 Merkle implementation,
a robust SSRF filter) and that all nine invariants have a proving test. It also
found that several load-bearing controls are not yet fully enforced in the running
server. The honest current state:

- HTTP transport is not implemented. v0 serves stdio only; an unsafe HTTP bind is
  refused (fails closed), but there is no HTTP server yet.
- The human-approval gate is a confirmation, not yet a human-binding control. The
  token is a deterministic function of the request and is returned in the dry-run
  response, so an automated caller can reproduce it. A server-issued, single-use,
  out-of-band nonce is proposed (BL-072).
- Tier authority is a denylist over the command string, and free-form shell
  actuation currently floors at T1, so a destructive command the denylist does not
  recognise can run without approval. Flooring arbitrary execution at T2 is
  proposed (BL-073).
- The read tools and `ingest_observation` bypass the single audited path, so those
  reads, and the one untrusted-driven state write, are not individually audited yet
  (BL-017, BL-062, BL-085).
- Scoped credentials, per-session budgets, an operator kill-switch actuator, and
  runtime Merkle/RFC 3161 audit anchoring are implemented or specified but not yet
  wired into the server (BL-049, BL-074, BL-075, BL-076). At runtime the audit
  trail is a keyless hash chain (written to an owner-only append-only file when
  `PRAXIS_AUDIT_PATH` is set, otherwise to stderr); external cryptographic anchoring
  is not produced automatically.

These and the rest are tracked as `BL-NNN` in `docs/backlog.md` with severities in
ADR-0015. `LIMITATIONS.md` is the running list of what is specified but not yet
delivered.

## Quickstart

`praxis` is self-contained: the default path is the SQLite store over stdio with no
external services.

```bash
uv sync --extra dev          # add --extra postgres for the production store backend
make check                   # ruff + mypy strict + pytest
make ci-success              # the above plus the schema-drift guard and eval gate
python -m praxis             # serve over stdio (JSON-RPC 2.0); refuses unsafe HTTP binds
```

Configuration is `PRAXIS_`-prefixed and bound once at import (`src/praxis/config.py`).
For the architecture and layout see `docs/architecture.md`; the nine non-negotiable
invariants are in `CLAUDE.md`.

## Layout

See `docs/architecture.md` for the full tree. The spine: `src/praxis/execution/`
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

Apache-2.0 (see `LICENSE`) and `NOTICE`.
