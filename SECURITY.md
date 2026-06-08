# Security model

`praxis` executes privileged operations across a host fleet. Security is the
primary design constraint, not an add-on. This document summarizes the model; the
authoritative hazard analysis lives in `docs/stpa/`.

## Threat model (summary)

The model-driven plane is the attack surface. Collected host data, command
output, retrieved documents, and external feeds are attacker-influenced and flow
back into the reasoning layer. The principal runtime risk is the "lethal trifecta":
simultaneous access to sensitive data, exposure to untrusted content, and an
actuation capability. The design keeps those three legs from coexisting in one
unguarded session.

## Controls (the nine invariants)

These nine are the design's load-bearing controls. Several are fully enforced with
tests; several are specified or partly built but not yet fully wired in v0. The
honest enforcement status is recorded in ADR-0015 and `LIMITATIONS.md`; the inline
notes below mark the v0 gaps.

1. Single audited execution path; no tool bypasses it.
2. Load-bearing tiered authority T0-T3; conservative classification;
   sudo/doas/pkexec are at least T2; modes gate tiers; deny is global and
   unconditional. (v0 gap: classification is a denylist over the command string and
   only rounds up, and free-form shell actuation floors at T1, so an unrecognised
   destructive command can run unapproved; the T2 floor for arbitrary execution is
   tracked as BL-073.)
3. Audit stores `output_sha256` + `output_len`, never output bodies; append-only
   per-entry hash chain; parameters redacted; the logger never raises.
4. Bitemporal, append-only state (deletion blocked at the storage layer;
   supersession carries actor and reason).
5. host_type gates actuation; never SSH a Talos host.
6. DRY_RUN, then human approval, then execute; T3 requires a typed token and one
   target at a time. (v0 gap: the approval token is a deterministic confirmation
   returned in the dry-run response, so an automated caller can reproduce it; it is
   not yet binding against an autonomous agent. A server-issued single-use nonce is
   tracked as BL-072.)
7. stdio by default; HTTP requires a bearer token AND an explicit non-loopback
   opt-in AND an SSRF egress filter (block link-local and RFC1918); no token
   passthrough. (The per-client consent registry named in ADR-0006 Decision 4 is
   specified but not yet built in v0; see `LIMITATIONS.md` and ADR-0012.)
8. Lethal-trifecta containment; read tools separable from act tools; human gate
   between observation and actuation.

Invariant 1 (single audited execution path) governs the execution and actuation
tools. In v0 the read tools (`query_facts`, `fact_history`, and the collector and
skill reads) and the state-writing `ingest_observation` tool read or write the store
directly without passing through `run()`, so they are not individually written to
the audit log; `ingest_observation` is `read_only=False` and arms the trifecta
latch, so the one untrusted-driven state write is currently unaudited. Routing them
through the audited path is tracked as BL-017, BL-062, and BL-085. Their feedback is
still treated as untrusted (invariant 8).
9. Least privilege; scoped, independently revocable credentials; kill switch; no
   NOPASSWD: ALL. (v0 gap: the `CredentialBroker` and `BudgetTracker` are
   implemented and tested but not wired into the actuation path, and the kill switch
   is enforced in the runner but has no operator-facing actuator; tracked as
   BL-049, BL-074, BL-075.)

Privileged-execution and audit hardening (the SSH host-key policy plus
option-injection target guard, subprocess process-group isolation with a scrubbed
environment and detached stdin, the talosctl verb allowlist and node-aware T3 gate,
audited trifecta refusals, the owner-only audit-log file mode, and broader secret
redaction) is recorded in ADR-0013. Each control has a regression test.

## Evidence integrity

At runtime the audit log is a per-entry, append-only hash chain (each record commits
to the previous record's hash). When `PRAXIS_AUDIT_PATH` is set (the recommended
operational config) the sink is an owner-only `O_APPEND` file; with no audit path the
logger writes to stderr, and it degrades to stderr if the file sink cannot be opened.
A periodic
Merkle root (RFC 6962 domain separation), an RFC 3161 timestamp, and an optional
transparency-log anchor (Rekor) are the designed evidence layer and a verifiable
library (`audit/evidence.py`), but in v0 the running server does not produce
checkpoints automatically, the default `LocalStamper` is keyless self-attestation,
and the real RFC 3161 backend is not implemented. So v0 tamper-evidence rests on the
hash chain plus, when an audit file is configured, operating-system append-only
storage (`chattr +a` or WORM); wiring
runtime anchoring and a non-forgeable stamper is tracked as BL-076 (with BL-050 for
tail-truncation detection). See ADR-0008 and ADR-0015.

## Reporting

Until a disclosure channel is published here, report security findings privately
to the maintainer. Do not open public issues for vulnerabilities.
