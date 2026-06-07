# First session: bootstrap brief for `praxis` (repo `aiops-mcp`)

This file is the kickoff brief for the first real Claude Code session in this
repository. It is self-sufficient: it does not require access to any other
repository. Work through the build sequence in order, keeping every change
traceable to a `BL-NNN` item in `docs/backlog.md`.

---

You are bootstrapping a brand-new, self-contained monorepo.

REPO: aiops-mcp
PRODUCT / PYTHON PACKAGE / CLI: praxis
ENV PREFIX: PRAXIS_
LICENSE: Apache-2.0
PYTHON: >=3.12

## Mission

Build praxis: a security-first, governed, single-operator-operable, EU-sovereign
"unified AI-operations MCP server". It maintains a live bitemporal model of a
heterogeneous host fleet, detects configuration drift (observed vs desired), and
actuates infrastructure and configuration operations through a single tiered,
audited execution path. It is the fleet's source of truth and its safe hands.

This is a GREENFIELD monorepo that implements EVERYTHING itself. It has ZERO
runtime dependency on, and makes NO imports from, any other repository. The
design guidance below is distilled from proven systems; reimplement it natively.

DOCUMENTATION STYLE (enforced): no em dashes and no double hyphens as prose
punctuation (backticked code flags like `--check` are fine). SI units, ISO 8601
dates, 24h UTC. Direct, technical tone, no marketing voice.

## Non-negotiable invariants (security-first; encode each as a test)

1. Single audited execution path. Every tool that can read or change a host goes
   through one entry point: classify tier, then policy check (deny-first,
   unconditional), then redact audited args, then contract
   preconditions/invariants, then execute, then bounded error formatting (never
   raw tracebacks), then truncate, then audit record. No tool bypasses it.
2. Tiered authority T0-T3 is load-bearing, not advisory. T0 observe (no
   approval); T1 reversible (act, log, notify); T2 stateful (human confirm with a
   rollback plan); T3 irreversible (two-step confirm with a typed token plus
   before/after evidence). classify() is conservative and rounds up. Any command
   containing sudo, doas, or pkexec is at least T2. Modes open/guarded/readonly
   gate which tiers may run; the deny list is global and applies in every mode.
3. Audit stores output_sha256 and output_len, NEVER output bodies. Append-only
   with a per-entry hash chain. Log parameters (redacted), not secret values. The
   audit writer is a separate concern from the audited process. Construction of
   the logger never raises (degrade to stderr).
4. State facts are bitemporal and append-only. Four timestamps (t_valid,
   t_invalid, t_recorded, t_superseded). Deletion is blocked at the storage
   layer; corrections supersede with an actor and a reason. At most one active
   fact per (subject, predicate, fact_type).
5. host_type gates actuation. Never open SSH to a Talos host (API-only,
   immutable; use talosctl). Branch ubuntu vs talos vs windows everywhere
   actuation happens.
6. Actuation is DRY_RUN first, then explicit human approval, then execute.
   Destructive (T3) operations require a typed confirmation token and operate on
   one target at a time.
7. MCP transport: stdio by default. HTTP requires a bearer token AND an explicit
   non-loopback opt-in AND an SSRF egress filter that blocks link-local and
   RFC1918 ranges. No token passthrough to upstreams. Per-client consent
   registry.
8. Lethal-trifecta containment. Never give one unguarded session simultaneous
   access to sensitive data, attacker-influenced content, and actuation. Treat
   all collected host data, command output, and external feeds as untrusted.
   Separate read tools from act tools; require a human gate between phases.
9. Least privilege. Scoped per-role credentials, independently revocable, with a
   kill switch (instant disable/revoke). No NOPASSWD: ALL.

## Architecture (strict layering: MCP tools -> skills -> services -> store/executor)

- MCP server surface: stdio default plus hardened streamable-HTTP opt-in; tools
  grouped state/query (read), drift (read), skills (read), actuation
  (tier-gated). Every tool carries accurate readOnly/destructive annotations.
- Fleet-state model: hosts, services, packages, storage pools, networks,
  interfaces, identities, alerts, drift findings, actuation requests, as typed
  vertices and edges; every fact bitemporal.
- Collectors, then normalize, then facts: read-only telemetry (osquery, AIDE,
  SSH probes, talosctl, WinRM/SSH, cloud API) normalized into fact envelopes.
- Drift engine: observe, then diff, then converge. Desired state from IaC plan
  (`tofu plan -refresh-only -json`), config baseline
  (`ansible-playbook --check --diff`), and an operator-blessed known-good
  snapshot. Emit structured drift findings as facts. Human-gated convergence.
- Tiered executor: the vendored, fused, audited execution core (below).
- Actuation adapters: wrap, do not reinvent. SSH/shell, OpenTofu, Ansible,
  runbook subprocess, talosctl, Redfish OOB, cloud API.
- Audit and evidence: hash chain plus periodic Merkle root plus RFC 3161
  timestamp plus optional Rekor anchor.
- Skills: host-knowledge skills ("what is") and tool skills ("how to operate").

## Repository layout

```
aiops-mcp/
  src/praxis/
    __main__.py            # env -> config -> store -> context -> MCP server
    config.py              # PRAXIS_-prefixed env, bound once at import
    server.py              # MCP wiring + transport guards (stdio/http)
    context.py             # ServerContext: transport, tier policy, classification
    execution/             # VENDORED + FUSED execution core
      patterns.py          # sole security-review file; PATTERNS_VERSION counter
      policy.py            # classify(tool, command) -> Tier; Policy.check
      redaction.py         # redact(), redact_args()
      audit.py             # append-only hash-chain logger; sha256+len, never body
      contract.py          # preconditions/invariants/postconditions, budgets, guard
      runner.py            # the single audited entry point (fused run)
    model/                 # vertices/edges, bitemporal fact types, host_type enum
    store/                 # StoreProtocol + ladder; sqlite (default) + postgres-age
    collectors/            # osquery, aide, ssh, talos, windows, cloud -> facts
    drift/                 # diff engine, desired-state sources, findings
    actuation/             # ssh, opentofu, ansible, runbook, talosctl, redfish, cloud
    skills/                # manifest, registry, dispatchers (routing chain)
    tools/                 # one MCP tool per file: register(mcp, ctx)
    audit/                 # supervisor writer, merkle, rfc3161, verify
  skills/                  # SKILL.md bundles (host-knowledge + tool), references/
  config/                  # inventory (seed fleet), osquery packs, hitl policy, scopes
  tests/                   # mirrors src/; PATH-shimmed fakes for actuation
  evaluation/              # dispatch P@1/MRR + drift regression gates + golden data
  deploy/                  # hardened Helm chart, systemd units, optional zarf
  docs/
    adr/                   # ADRs + README index
    stpa/                  # losses, hazards, constraints, control structure, UCAs,
                           #   loss scenarios, security constraints
    backlog.md             # BL-NNN tracker (stable IDs, source ADR, never delete)
    governance/            # compliance mapping (EU AI Act/NIS2/CRA/GDPR/ISO 27001)
    runbooks/              # operate + periodic self-audit
  CLAUDE.md AGENTS.md README.md SECURITY.md LIMITATIONS.md CHANGELOG.md
  CONTRIBUTING.md LICENSE NOTICE Makefile pyproject.toml
  .github/workflows/       # ci, codeql, sbom, dependency-review, fuzz (pinned SHAs)
```

## Build sequence (do strictly in this order; commit per step with BL-NNN refs)

0. Governance first (already seeded in this bootstrap: ADR-0001, the STPA
   skeleton, and the backlog). Extend it: write ADR-0002 through ADR-0010 (listed
   in `docs/adr/README.md`) and flesh out `docs/stpa/` BEFORE the code that
   depends on each decision, so the code traces to it.
1. Repo skeleton finishing touches: add the full Apache-2.0 LICENSE text (BL-001),
   complete `pyproject.toml` (ruff + mypy strict + pytest), and the `Makefile`
   targets (`make check` = lint + type-check + test; plus schema and eval).
2. Execution core (vendored + fused). patterns.py (Tier enum; TIER2/TIER3 and
   priv-escalation regexes; PATTERNS_VERSION), policy.py (classify conservative
   round-up; deny-first Policy.check; open/guarded/readonly modes), redaction.py,
   audit.py (append-only JSONL, sha256+len, hash chain, never body, degrade to
   stderr), contract.py (predicates with HARD/SOFT severity; budget tracker
   rejecting non-finite inputs; tool guard; approval-required; retry at most once
   requiring fresh approval), runner.py (the single fused entry point). Exhaustive
   tests for the invariants.
3. State store. StoreProtocol L1 plus extension ladder (implement only what a
   backend honours). SQLite backend (default): bitemporal fact tables, an
   append-only delete-blocking trigger, supersession with actor and reason, the
   active-fact unique constraint, sqlite-vec for embeddings, edge tables for the
   graph. Postgres+AGE backend (production) behind the same Protocol. Round-trip,
   temporal-history, and append-only tests against both (skip Postgres cleanly
   when absent).
4. Model and collectors. Fact envelopes and host_type. osquery and AIDE
   collectors first (read-only), then ssh/talos/windows/cloud. Normalize to facts;
   write to the store. Tests with fixtures, no live hosts.
5. Drift engine. Desired-state sources (tofu plan, ansible check, known-good
   snapshot); diff to findings; write findings as facts; reconciliation framing
   with a human gate. Regression fixtures in evaluation/.
6. Actuation adapters. Wrap each tool; enforce host_type; DRY_RUN, then approve,
   then execute; typed tokens and one-target-at-a-time for T3. PATH-shimmed fakes
   in tests (never call the real tool).
7. Skills engine. Manifest plus registry plus routing-chain dispatcher;
   host-knowledge and tool skills; allow_contract=False for untrusted bundles;
   eval gate (P@1/MRR) and schema-drift guard in CI.
8. Audit and evidence. Supervisor writer; Merkle (RFC 6962 domain separation);
   RFC 3161 stamping (fail-closed verify); optional Rekor; verify CLI. Bind the
   server-binary hash into the session header.
9. MCP server surface. config.py (PRAXIS_ env, bound at import), server.py and
   context.py (stdio default; HTTP token plus non-loopback opt-in plus SSRF egress
   filter; per-client consent), tools/ (read tools first, then tier-gated
   actuation tools, each with accurate readOnly/destructive annotations and an
   audit call). Tests prove HTTP refuses non-loopback bind without the opt-in and
   without a token; that destructive tools cannot run without the approval flow;
   that output bodies are never logged.
10. CI and deploy. `.github/workflows/` (ci, codeql, sbom, dependency-review,
    nightly fuzz; pinned action SHAs; least-privilege permissions), all gated by a
    `ci-success` aggregate. Hardened Helm chart (PSA restricted, default-deny
    NetworkPolicy, digest-pinned, per-component SA no automount), systemd units
    with hardening drop-ins, optional zarf for airgap.
11. Seed data. config/inventory: the target fleet (see `config/inventory.example.yaml`)
    with host_type, routing, and posture as DATA, not code. A migration note for
    importing the prototype's host-knowledge and known-good baselines into the new
    model (backlog item).

## Definition of done for v0.1

- `make check` green (ruff + mypy strict + pytest), schema-drift guard and eval
  gate green, all in `ci-success`.
- The nine invariants each have at least one passing test.
- Every state-changing MCP tool appears in the STPA UCA table; every STPA
  security constraint maps to a code assertion, policy rule, or HITL gate.
- A fixture host snapshot diffed against a known-good baseline yields the expected
  drift findings (regression test).
- The MCP server runs over stdio against the SQLite store with no external
  services, and refuses unsafe HTTP binds.

## Trusted external sources

STPA Handbook (Leveson and Thomas, MIT) and STPA-Sec; MCP security best practices
and authorization spec (modelcontextprotocol.io), NSA MCP guidance, the "lethal
trifecta" (Simon Willison), CSA agentic MCP; OpenTofu/Terraform drift
(`plan -refresh-only`), osquery FIM, Kubernetes/GitOps reconciliation; RFC 6962
(Certificate Transparency), Rekor/Sigstore, RFC 3161.

START by writing ADR-0001 review and ADR-0002, then finish the repo skeleton
(LICENSE, pyproject, Makefile), then proceed through the build sequence. Keep
changes surgical and traceable to a BL-NNN backlog item. Do not weaken a default
to make something pass.
