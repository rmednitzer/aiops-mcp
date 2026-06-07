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

1. Single audited execution path; no tool bypasses it.
2. Load-bearing tiered authority T0-T3; conservative classification;
   sudo/doas/pkexec are at least T2; modes gate tiers; deny is global and
   unconditional.
3. Audit stores `output_sha256` + `output_len`, never output bodies; append-only
   per-entry hash chain; parameters redacted; the logger never raises.
4. Bitemporal, append-only state (deletion blocked at the storage layer;
   supersession carries actor and reason).
5. host_type gates actuation; never SSH a Talos host.
6. DRY_RUN, then human approval, then execute; T3 requires a typed token and one
   target at a time.
7. stdio by default; HTTP requires a bearer token AND an explicit non-loopback
   opt-in AND an SSRF egress filter (block link-local and RFC1918); no token
   passthrough; per-client consent registry.
8. Lethal-trifecta containment; read tools separable from act tools; human gate
   between observation and actuation.
9. Least privilege; scoped, independently revocable credentials; kill switch; no
   NOPASSWD: ALL.

## Evidence integrity

Beyond the per-entry hash chain, the audit log is periodically committed to a
Merkle root (RFC 6962 domain separation), anchored by an RFC 3161 timestamp and
optionally a transparency log (Rekor). The audit writer is architecturally
separated from the audited process; signing keys are isolated from the tool
execution environment.

## Reporting

Until a disclosure channel is published here, report security findings privately
to the maintainer. Do not open public issues for vulnerabilities.
