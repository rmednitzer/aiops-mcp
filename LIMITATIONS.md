# Limitations and scope boundaries

This file states what `praxis` is not, and the known gaps at the current phase.

## Phase

v0 implemented and gated, in iterative security hardening. The execution core,
store (SQLite default, Postgres+AGE optional), collectors, drift engine, actuation
adapters, skills engine, tamper-evident audit, and the MCP stdio surface are built
and tested; `make ci-success` is green and each of the nine invariants has a passing
test. Hardening proceeds through the audit waves (ADR-0011 through ADR-0013); the
open items in `docs/backlog.md` (notably the HTTP transport, hostname-resolving
SSRF, credential wiring, and CI/deploy gating) are tracked, not yet delivered.

## Scope boundaries

- Not a model-training or model-serving platform. It operates infrastructure; it
  does not host inference workloads.
- Not a general SIEM. It tracks host/fleet state and drift; it integrates with,
  but does not replace, log pipelines or detection engines.
- Not a replacement for IaC or configuration management. It WRAPS OpenTofu,
  Ansible, runbooks, and talosctl; the desired-state authorities remain those
  tools.

## Known gaps (to be closed via the backlog)

- Capability isolation for actuation subprocesses (container/seccomp) is an
  out-of-tree extension point at v0.
- Multi-operator/multi-tenant authorization is not a v0 goal; the default posture
  is single-operator with scoped credentials.
- Windows actuation depth (beyond observation) is staged after the Linux and
  Talos paths.
- The per-client consent ceiling named in ADR-0006 (Decision 4) is specified but
  not implemented in v0 (ADR-0012, BL-045). The transport guard, SSRF filter,
  token requirement, and non-loopback opt-in are in place; the consent registry
  is not.
- Read-only tools (`query_facts`, `fact_history`, collector and skill reads) read
  the store directly and are not individually written to the audit log in v0.
  Invariant 1's single audited path covers the execution and actuation tools;
  routing reads through it is tracked as BL-062. Read feedback is still treated as
  untrusted (invariant 8).
