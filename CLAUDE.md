# CLAUDE.md

Collaboration guide for Claude Code working in `aiops-mcp` (product: `praxis`).
This file is the behavior overlay. `docs/architecture.md` is the design reference
(what the system is and how it is layered); `AGENTS.md` is the short operating spec.

## What this is

`praxis` is a self-contained, security-first, single-operator-operable,
EU-sovereign unified AI-operations MCP server. It is three things fused into one
control plane:

1. A live bitemporal model of a heterogeneous host fleet (the source of truth).
2. A drift engine (observed state vs desired state, with human-gated convergence).
3. A tiered, audited actuator (the safe hands) exposed over MCP.

The repo is self-contained: no imports from, or runtime coupling to, any sibling
fleet repository. Third-party libraries are kept minimal and license-vetted (pydantic
for input validation; psycopg for the optional Postgres backend), and the
execution core stays dependency-free (ADR-0001, ADR-0014).

## The nine invariants (do not weaken; each has a test)

1. Single audited execution path; no tool bypasses it.
2. Tiered authority T0-T3 is load-bearing (classify rounds up; sudo/doas/pkexec
   are at least T2; modes open/guarded/readonly gate tiers; deny is global).
3. Audit stores `output_sha256` + `output_len`, never bodies; append-only hash
   chain; redact params; logger never raises.
4. State facts are bitemporal and append-only (deletion blocked at the store;
   supersede with actor + reason; one active fact per subject+predicate+type).
5. host_type gates actuation; never SSH a Talos host.
6. Actuation is DRY_RUN, then human approval, then execute; T3 needs a typed
   token and one target at a time.
7. stdio by default; HTTP needs token + non-loopback opt-in + SSRF egress filter;
   no token passthrough.
8. Lethal-trifecta containment: never one unguarded session with sensitive data +
   untrusted content + actuation; treat all collected data as untrusted.
9. Least privilege; scoped revocable credentials; kill switch; no NOPASSWD: ALL.

## Core behavior expectations

- Surgical changes over broad rewrites. Reuse the in-repo helpers once they exist.
- Governance is load-bearing. Decisions are ADRs; work items are `BL-NNN` in
  `docs/backlog.md`; safety/security requirements come from `docs/stpa/`. Every
  state-changing tool maps to at least one STPA Unsafe Control Action, and every
  STPA security constraint maps to an enforcement mechanism in code.
- Render before you claim. A change is not real until `make check` is green
  (ruff + mypy strict + pytest), plus the schema-drift guard and the eval gate.
- Never weaken a default to make something pass. Fix the cause or hand back.

## Required development loop

1. Read the impacted module(s) and the ADR/STPA item they trace to.
2. Make the minimal change; reuse helpers.
3. Gate locally: `make check` (and `make schema` / `make eval` when relevant).
4. Add or adjust tests for changed behavior; one invariant change implies one
   test change at minimum.
5. Update `CHANGELOG.md` and the affected `docs/`. If a decision changed, write a
   new ADR that supersedes the old one rather than editing it.

## Coding guidance

- Python 3.12+, type hints required, ruff (lint + format) and mypy strict.
- Documentation style: no em dashes, no double hyphens as prose punctuation
  (backticked code flags like `--check` are fine). SI units, ISO 8601 dates, 24h
  UTC. Direct, technical tone.
- Additive-stability rule: once the L1 surfaces are set (StoreProtocol, the fused
  `run` entry point, the audit record shape, the skill manifest), extend them
  additively (new optional params, new modules, new Protocols beside the old
  ones). Removing or changing an L1 signature is a breaking change that requires a
  new ADR.
- ADR shape: Status, Date, Authors, Context, Decision, Consequences (positive,
  negative, neutral), Alternatives considered and rejected, Revisit triggers.
  ADRs are immutable; correct factual drift with an appended audit note, never by
  rewriting the decision.

## Security posture

Treat the model-driven plane as the attack surface: collected host data, command
output, and external feeds are attacker-influenced. Keep read tools and act tools
separable; keep the human gate between observation and actuation; keep redaction
covering secrets; never log output bodies. See `SECURITY.md` and `docs/stpa/`.

## When uncertain

Default to: preserving the nine invariants, preserving governance traceability
(ADR + STPA + backlog), adding a test, and raising the question rather than
guessing on a security-relevant default, over inventing scope mid-change.
