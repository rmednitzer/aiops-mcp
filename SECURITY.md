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

These nine are the design's load-bearing controls, each with a proving test. The
enforcement history is recorded in ADR-0015 (the gap review) and ADR-0016 (the
wave that closed them); `LIMITATIONS.md` records what remains open.

1. Single audited execution path; no tool bypasses it. Since ADR-0016 this
   includes the read tools and `ingest_observation` (BL-017, BL-062, BL-085).
2. Load-bearing tiered authority T0-T3; conservative classification;
   sudo/doas/pkexec are at least T2; modes gate tiers; deny is global and
   unconditional. Free-form shell actuation floors at T2 (ADR-0016, BL-073),
   because the denylist only rounds up and cannot be complete against arbitrary
   commands.
3. Audit stores `output_sha256` + `output_len`, never output bodies; append-only
   per-entry hash chain; parameters redacted; the logger never raises.
4. Bitemporal, append-only state (deletion blocked at the storage layer;
   supersession carries actor and reason).
5. host_type gates actuation; never SSH a Talos host.
6. DRY_RUN, then human approval, then execute; T3 requires a typed token and one
   target at a time. The approval is a server-minted, single-use, TTL-bound nonce
   surfaced out-of-band on the operator console, never in a tool response, so an
   autonomous caller cannot self-approve (ADR-0016, BL-072).
7. stdio by default; HTTP requires a bearer token AND an explicit non-loopback
   opt-in AND an SSRF egress filter (block link-local and RFC1918); no token
   passthrough. (The per-client consent registry named in ADR-0006 Decision 4 is
   specified but not yet built in v0; see `LIMITATIONS.md` and ADR-0012.)
8. Lethal-trifecta containment; read tools separable from act tools; human gate
   between observation and actuation, enforced inside the single audited path
   (ADR-0016, BL-083): once the session has taken in untrusted content, including
   observed facts read back from the store, any T1+ real run needs a minted
   approval.
9. Least privilege; scoped, independently revocable credentials (broker wired,
   opt-in via the first grant); per-session budgets; an audited `emergency_stop`
   actuator with a durable kill-switch sentinel; no NOPASSWD: ALL (ADR-0016,
   BL-049, BL-074, BL-075).

Privileged-execution and audit hardening (the SSH host-key policy plus
option-injection target guard, subprocess process-group isolation with an
allowlisted environment and detached stdin, the talosctl verb allowlist, post-verb
option rejection, node validation, explicit reset wipe scope and node-aware T3
gate, playbook/runbook root confinement, the owner-only audit-log and store file
modes, and broader secret redaction) is recorded in ADR-0013 and ADR-0016. Each
control has a regression test.

## Evidence integrity

At runtime the audit log is a per-entry, append-only hash chain (each record commits
to the previous record's hash). When `PRAXIS_AUDIT_PATH` is set (the recommended
operational config) the sink is an owner-only `O_APPEND` file; with no audit path the
logger writes to stderr, and it degrades to stderr if the file sink cannot be opened.
Since ADR-0019 (BL-076) the running server also produces Merkle checkpoints (RFC
6962 domain separation) over the log: every `PRAXIS_EVIDENCE_EVERY` records
(default 64) and at orderly shutdown, into `PRAXIS_EVIDENCE_PATH` (default
`<audit>.evidence.jsonl`). With `PRAXIS_ANCHOR_PATH` set, each checkpoint head is
also appended to an anchor file that `verify_audit.py` cross-checks, so rewriting
both the log and the evidence file to a shorter consistent history is detected
(BL-050); the anchor earns that property only when it lives on a different trust
domain (another filesystem, host, or WORM store). The remaining boundary: the
default `LocalStamper` is keyless self-attestation, so an attacker who can rewrite
all three files is outside the detectable set; a non-forgeable RFC 3161 TSA stamper
is available opt-in (`PRAXIS_TSA_URL` plus the `tsa` extra; BL-095, ADR-0030).
Operating-system append-only storage (`chattr +a` or WORM) on those files remains a
required deploy control while the default `LocalStamper` is in use. See ADR-0008,
ADR-0019, ADR-0030.

## Retention

The audit and evidence retention tiers are bound in configuration as the single
source of truth (BL-035): `PRAXIS_AUDIT_RETENTION_DAYS` and
`PRAXIS_EVIDENCE_RETENTION_DAYS` (both default 365 days; `0` retains indefinitely;
the anchor file follows the evidence tier). The declared policy is written into the
first session audit record, so the retention in force is part of the tamper-evident
trail, not documentation alone (NIS2 Art. 23, ISO 27001 A.8.15).

Enforcement is at the storage layer, not in the server. The trail is append-only by
construction (the audit hash chain and the evidence and anchor files are never
rewritten in place; invariant 4, SEC-9, SEC-10), so a tier is applied by time-based
archival of whole files older than the tier (an archive-then-rotate job, or a WORM
store with a retention class), never an in-place truncate or a `logrotate`
`copytruncate`, which would break the chain and the `O_APPEND` owner-only sink.
Archive a closed audit file together with its `.evidence.jsonl` and anchor sidecars
so a verifier can still replay a retained window end to end with
`scripts/verify_audit.py`. A tier of `0` plus operating-system append-only storage
(`chattr +a` or WORM) is the most conservative posture.

## Reporting

Until a disclosure channel is published here, report security findings privately
to the maintainer. Do not open public issues for vulnerabilities.
