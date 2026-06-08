# Limitations and scope boundaries

This file states what `praxis` is not, and the known gaps at the current phase.

## Phase

v0 implemented and gated, in iterative security hardening. The execution core,
store (SQLite default, Postgres+AGE optional), collectors, drift engine, actuation
adapters, skills engine, tamper-evident audit, and the MCP stdio surface are built
and tested; `make ci-success` is green and each of the nine invariants has a passing
test. Hardening proceeds through the audit waves (ADR-0011 through ADR-0015); the
open items in `docs/backlog.md` (notably the HTTP transport, the human-binding
approval gate, the free-form-shell tier floor, hostname-resolving SSRF, credential
and budget wiring, runtime audit anchoring, and CI/deploy gating) are tracked, not
yet delivered.

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

## Specified or built but not yet wired (ADR-0015, 2026-06-08)

The deep review confirmed the spine is sound and that all nine invariants have a
proving test, and it also found load-bearing controls that the running server does
not yet enforce as the design states. These are facts about the v0 code, recorded
here for honesty and tracked in the backlog:

- The human-approval gate is not human-binding. `expected_token` is a deterministic
  function of the request (`APPROVE-<action_id>` at T2, `CONFIRM-<target>` at T3)
  and is returned in the `DRY_RUN` response, so an automated caller can reproduce
  it and self-approve. A server-issued, single-use, out-of-band nonce is proposed
  (BL-072).
- Tier authority is a denylist over the command string and only ever rounds up;
  free-form shell actuation (the SSH adapter) carries `base_tier=T1`, so a
  destructive command the patterns do not recognise (for example `find / -delete`,
  `nft flush ruleset`, `iptables -F`, an `authorized_keys` append) runs at T1 with
  no approval. Flooring arbitrary execution at T2 is proposed (BL-073).
- `ingest_observation` writes observed facts and arms the trifecta latch yet
  bypasses `run()`, so the one untrusted-driven state write is unaudited and is not
  in the UCA table (BL-085).
- `CredentialBroker` (scoped, revocable credentials) and `BudgetTracker`
  (per-session action, cost, and wall-time ceilings) are implemented and tested but
  never instantiated in the running server, so neither enforces anything at runtime
  (BL-049, BL-074).
- The kill switch is checked on every call but has no operator-facing actuator
  (no MCP tool, no signal handler, no file sentinel); only the unwired broker's
  `kill_all` trips it, and the trip state is not durable across a restart (BL-075).
- Runtime audit anchoring is not produced. The server writes the per-entry hash
  chain and the session header, but never invokes Merkle checkpointing or RFC 3161
  stamping; the default `LocalStamper` is keyless self-attestation and the real TSA
  raises `NotImplementedError`. v0 tamper-evidence rests on the hash chain plus
  operating-system append-only storage (`chattr +a` or WORM); wiring runtime
  anchoring and a non-forgeable stamper is tracked as BL-076 (with BL-050 for
  tail-truncation detection).
- The SQLite store file is created with the default umask, not `0o600`, so
  restricted facts may be group or world readable on a shared host (BL-079); wrapped
  actuation subprocesses inherit the full server environment, including unrelated
  secrets (BL-080).
