# AIOps-MCP

**praxis**, the unified AI-operations MCP.

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/rmednitzer/aiops-mcp)

Documentation site (rendered from `docs/`): <https://rmednitzer.github.io/aiops-mcp/>

> Status: v0, stdio default with an opt-in HTTP transport, single-operator, in
> iterative security hardening.
> `make ci-success` is green (ruff + mypy strict + pytest + the schema-drift guard +
> the dispatch eval gate) and each of the nine invariants has a passing test, but
> a deep review (ADR-0015) found that several controls the design treats as
> load-bearing are specified and partly built yet not fully wired into the running
> server. Read "Maturity and honest limitations" below and `LIMITATIONS.md` before
> relying on it. Audit and feature waves: ADR-0011 through ADR-0042; open work is in
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
a robust SSRF filter) and that all nine invariants have a proving test; the
ADR-0016 enforcement wave (2026-06-10) closed its P1 and wiring findings. The
honest current state:

- HTTP transport is implemented and opt-in (ADR-0041): a stdlib `http.server` with an
  `Mcp-Session-Id` session lifecycle, per-session isolation (each session has its own
  trifecta taint latch, approval nonces, budget, and consent ceiling), constant-time
  bearer-token auth, a request-body cap, and a per-client consent ceiling. It stays
  default-closed (token + non-loopback opt-in + SSRF egress, ADR-0006); stdio is still
  the default. Serving is concurrent (ADR-0042, BL-110): a `ThreadingHTTPServer` over a
  store that serialises on a per-instance lock, so a slow actuation does not block other
  clients while the bitemporal/append-only invariants hold.
- The human-approval gate is human-binding (ADR-0016, BL-072): a gated dry run
  mints a server-generated, single-use, TTL-bound token surfaced on the operator
  console, out-of-band from the MCP channel. The token never appears in a tool
  response, so an automated caller cannot reproduce or replay it. Free-form shell
  actuation floors at T2 (BL-073).
- Every registered tool, including the read tools and `ingest_observation`, runs
  through the single audited path (BL-017, BL-062, BL-085); reads that return
  observed facts arm the trifecta latch, enforced inside the path (BL-083).
- Scoped credentials (opt-in via the first grant), per-session budgets, and an
  audited `emergency_stop` actuator with a durable kill-switch sentinel are wired
  (BL-049, BL-074, BL-075). With `PRAXIS_AUDIT_PATH` set, the server also produces
  runtime Merkle checkpoints over the trail (every N records and at shutdown) and
  an optional anchored high-water mark (`PRAXIS_ANCHOR_PATH`) that detects
  truncation of log plus evidence together (ADR-0019; BL-076, BL-050). The default
  checkpoint stamper is the keyless `LocalStamper`; a non-forgeable RFC 3161 TSA
  stamper is available opt-in (`PRAXIS_TSA_URL` plus `PRAXIS_TSA_CERT`, the TSA signing
  certificate in PEM, plus the `tsa` extra; BL-095, ADR-0030). With the default stamper,
  OS-level append-only storage remains the required control against an attacker who can
  rewrite the files. Audit records can also be forwarded best-effort to syslog for
  SIEM/journald visibility (`PRAXIS_AUDIT_SYSLOG_ADDRESS`, opt-in); the append-only file
  stays the authoritative, tamper-evident sink (BL-100, ADR-0037). Each record carries
  optional `request_id` / `client_id` correlation fields, set per request by the
  transport, so concurrent calls can be tied to their audit entries (BL-101, ADR-0038).

These and the rest are tracked as `BL-NNN` in `docs/backlog.md` with severities in
ADR-0015. `LIMITATIONS.md` is the running list of what is specified but not yet
delivered.

## Quickstart

For a complete, task-oriented walkthrough of running the server and using every tool, see
the [how-to guide](docs/guide.md) (also on the docs site).

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
