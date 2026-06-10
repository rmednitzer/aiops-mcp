# Architecture

The durable design reference for `praxis` (repo `aiops-mcp`). It describes what the
system is and how it is layered. `CLAUDE.md` is the behavior overlay (and holds the
nine non-negotiable invariants); `AGENTS.md` is the short operating spec; standing
decisions are ADRs under `docs/adr/`; safety and security requirements are derived
in `docs/stpa/`; work is tracked as `BL-NNN` in `docs/backlog.md`.

## What praxis is

A self-contained, security-first, single-operator-operable, EU-sovereign unified
AI-operations MCP server. It fuses three things into one control plane:

1. A live bitemporal model of a heterogeneous host fleet (the source of truth):
   hosts, services, packages, storage pools, networks, interfaces, identities,
   alerts, drift findings, and actuation requests as typed vertices and edges, every
   fact carrying four timestamps and never deleted (corrections supersede).
2. A drift engine: observed host state versus desired state (an IaC plan, a config
   baseline, or an operator-blessed known-good snapshot), emitting structured drift
   findings as facts, with human-gated convergence.
3. A tiered, audited actuator: a single execution path that classifies every action
   T0 to T3, gates state-changing actions behind human confirmation, and wraps the
   right tool per host type instead of reinventing it.

It is self-contained: no imports from, or runtime coupling to, any sibling fleet
repository. Third-party libraries are kept minimal and license-vetted (pydantic for
input validation; psycopg for the optional Postgres backend), and the execution core
stays dependency-free (ADR-0001, ADR-0014).

## Strict layering

The surface is layered: MCP tools, then skills, then services (the collectors, the
drift engine, the actuation adapters, and the evidence layer), then the store and
the execution core. Each layer has one responsibility and a stable contract:

- MCP server surface (`src/praxis/server.py`, `src/praxis/tools/`): stdio is the v0
  transport. A streamable-HTTP transport is staged behind an enforced guard (a bearer
  token plus an explicit non-loopback opt-in plus the SSRF egress filter); the server
  validates that guard and fails closed on an unsafe HTTP bind, but HTTP serving
  itself is not yet implemented (it raises `NotImplementedError`), so v0 serves stdio
  only. Tools are grouped state/query (read), drift (read), skills (read), and
  actuation (tier-gated), each carrying accurate `readOnly`/`destructive`
  annotations. The registry is transport-agnostic.
- Skills (`src/praxis/skills/`): a manifest plus a registry plus a routing-chain
  dispatcher. Host-knowledge skills ("what is") and tool skills ("how to operate").
  Untrusted bundles load inert (`allow_contract=False`); a dispatch P@1/MRR eval gate
  and a JSON-Schema drift guard run in CI.
- Fleet-state model and store (`src/praxis/model/`, `src/praxis/store/`): the
  bitemporal fact and edge types and the `host_type` enum behind one `StoreProtocol`,
  with an extension ladder a backend implements only where it can honour it. SQLite
  is the default (storage-layer append-only triggers, the active-fact unique index,
  supersession with actor and reason); Postgres + Apache AGE is the production
  backend behind the same Protocol.
- Collectors and drift (`src/praxis/collectors/`, `src/praxis/drift/`): read-only
  telemetry (osquery, AIDE, SSH/WinRM probes, talosctl) normalized into fact
  envelopes, and the observed-versus-desired diff that emits findings. Collected data
  is untrusted and is only compared, never interpreted as instructions.
- Execution core (`src/praxis/execution/`): the single audited, tier-aware execution
  path (`patterns`, `policy`, `redaction`, `audit`, `contract`, `runner`).
  `patterns.py` is the sole security-review file. Every registered tool, read or
  write, passes through `run()` (ADR-0016; the read tools and `ingest_observation`
  route via `tools/_audited.py`): kill switch, contained arg redaction, classify,
  deny-first policy, budget, approval and trifecta gate, contract preconditions,
  execute, bounded error, hash and length, truncate, audit. A gated DRY_RUN mints
  a server-generated, single-use, TTL-bound approval nonce surfaced OUT-OF-BAND on
  the operator console, never in a tool result (BL-072).
- Actuation adapters (`src/praxis/actuation/`): wrappers (never reinventions) for
  SSH/shell, OpenTofu, Ansible, runbook subprocess, and talosctl. Each enforces
  `host_type` as a HARD audited precondition, and follows DRY_RUN then approve then
  execute, with minted single-use approvals and one-target-at-a-time for T3.
  Free-form shell (the SSH adapter) floors at T2 (ADR-0016, BL-073); ansible and
  runbook actions are confined to configured roots, fail closed when unset; the
  subprocess environment is an allowlist (BL-080).
- Audit and evidence (`src/praxis/audit/`): the per-entry hash chain plus a periodic
  Merkle root (RFC 6962 domain separation) plus RFC 3161 timestamping (fail-closed
  verify) plus an optional transparency-log anchor. The session header binds the
  server-binary hash into the trail. The Merkle and RFC 3161 layer is built and
  verifiable, but the running server does not produce checkpoints in v0 (the default
  stamper is keyless; the real TSA is unimplemented), so runtime tamper-evidence is
  the hash chain plus operating-system append-only storage when an audit file is
  configured (`PRAXIS_AUDIT_PATH`; otherwise audit records go to stderr) (BL-076).

## Repository layout

```
aiops-mcp/
  src/praxis/
    __main__.py            # env -> config -> store -> context -> MCP server
    config.py              # PRAXIS_-prefixed env, bound once at import
    server.py              # MCP wiring + transport guards (stdio/http)
    context.py             # ServerContext: transport, trifecta gate, classification
    execution/             # the vendored, fused, audited execution core
    model/                 # vertices/edges, bitemporal fact types, host_type enum
    store/                 # StoreProtocol + ladder; sqlite (default) + postgres-age
    collectors/            # osquery, aide, ssh/probe, talos -> facts
    drift/                 # diff engine, desired-state sources, findings, converge
    actuation/             # ssh, opentofu, ansible, runbook, talosctl, credentials
    skills/                # manifest, registry, routing-chain dispatcher, eval
    tools/                 # one MCP tool per file: register(registry)
    audit/                 # merkle, rfc3161, evidence, session header
  skills/                  # SKILL.md bundles (host-knowledge + tool), references/
  config/                  # seed fleet inventory (host_type, routing, posture as data)
  tests/                   # mirrors src/; PATH-shimmed fakes for actuation
  evaluation/              # dispatch P@1/MRR + drift regression gates + golden data
  deploy/                  # hardened Helm chart, systemd units, optional zarf
  docs/
    architecture.md        # this file
    adr/                   # ADRs + README index
    stpa/                  # losses, hazards, constraints, control structure, UCAs, ...
    backlog.md             # BL-NNN tracker (stable ids, source ADR, never deleted)
    governance/            # compliance mapping (EU AI Act/NIS2/CRA/GDPR/ISO 27001)
    runbooks/              # operate + periodic self-audit
  CLAUDE.md AGENTS.md README.md SECURITY.md LIMITATIONS.md CHANGELOG.md
  CONTRIBUTING.md LICENSE NOTICE Makefile pyproject.toml
  .github/workflows/       # ci, codeql, sbom, dependency-review, fuzz (pinned SHAs)
```

## Trusted external sources

The design is distilled from proven systems and reimplemented natively: the STPA
Handbook (Leveson and Thomas, MIT) and STPA-Sec; MCP security best practices and the
authorization spec (modelcontextprotocol.io), NSA MCP guidance, the "lethal trifecta"
(Simon Willison), CSA agentic MCP; OpenTofu/Terraform drift (`plan -refresh-only`),
osquery FIM, Kubernetes/GitOps reconciliation; RFC 6962 (Certificate Transparency),
Sigstore/transparency logs, and RFC 3161.
