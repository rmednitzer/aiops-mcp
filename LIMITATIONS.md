# Limitations and scope boundaries

This file states what `praxis` is not, and the known gaps at the current phase.

## Phase

v0 implemented and gated, in iterative security hardening. The execution core,
store (SQLite default, Postgres+AGE optional), collectors, drift engine, actuation
adapters, skills engine, tamper-evident audit, and the MCP stdio surface are built
and tested; `make ci-success` is green and each of the nine invariants has a passing
test. Hardening proceeds through the audit and feature waves (ADR-0011 through
ADR-0040). The ADR-0016 wave delivered the human-binding approval gate
(server-minted, single-use, TTL-bound nonces surfaced out-of-band), the T2 floor for
free-form shell, in-path trifecta containment, audited reads and ingest, and the
budget, kill-switch actuator, and credential-broker wiring. Several items once listed
here as open have since landed: hostname-resolving SSRF (BL-046, ADR-0025), runtime
audit anchoring and Merkle checkpoints (BL-076/050, ADR-0019), the RFC 3161 TSA
stamper (BL-095, ADR-0030), CI/deploy gating (BL-052, ADR-0036), the multi-client
HTTP transport (BL-012, ADR-0041): the serving loop is built (per-session isolation,
constant-time bearer auth, a body cap, and the per-client consent ceiling), and concurrent
serving over a thread-safe store (BL-110, ADR-0042): every store method serialises on a
per-instance lock and the transport is a `ThreadingHTTPServer`, so requests run in parallel
(a slow actuation no longer blocks other clients) without weakening the
bitemporal/append-only invariants. stdio remains the default and the simplest deployment.

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
- The running server produces Merkle checkpoints (every `PRAXIS_EVIDENCE_EVERY`
  records, default 64, and at orderly shutdown) plus an optional anchored
  high-water mark (`PRAXIS_ANCHOR_PATH`) when an audit file is configured
  (ADR-0019; BL-076, BL-050). The remaining gaps: the default `LocalStamper` is
  keyless self-attestation (its token is forgeable by anyone who can write the
  evidence file); a non-forgeable RFC 3161 TSA stamper is now available opt-in
  (`PRAXIS_TSA_URL` plus `PRAXIS_TSA_CERT`, the PEM signing certificate, plus the `tsa`
  extra; BL-095, ADR-0030) but is off by default;
  a crash leaves an uncovered audit tail that `verify_evidence` flags (the intended
  visible seam, not silent loss); and the anchor only helps if the operator places
  it on a different trust domain than the audit log. Operating-system append-only
  storage (`chattr +a` or WORM) on the audit, evidence, and anchor files remains a
  required deploy control for attacker-grade tamper-evidence while the default
  `LocalStamper` is in use. With no `PRAXIS_AUDIT_PATH`, or on a file-open failure, records
  go to stderr and no evidence is produced.
- The minted approval nonce is surfaced on the server's stderr (the operator
  console). Over stdio that stream belongs to the process that launched the
  server, so an operator using a desktop MCP client reads the token from that
  client's server-log view; a first-class operator channel (for example MCP
  elicitation) is a revisit trigger in ADR-0016.
- The credential broker enforces scopes only once the operator issues a grant,
  and grants are in-process (no MCP grant tool, no persistence); zero grants is
  the single-operator default with no scope gate.
- The skill and collector READS outside the five registered tools (the skills
  dispatcher's internal reads) do not individually write audit records; the five
  MCP tools all route through the single audited path since ADR-0016.
