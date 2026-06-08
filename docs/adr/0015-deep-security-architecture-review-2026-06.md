# ADR-0015: Deep security and architecture review (2026-06) and proposed remediation wave

| Field   | Value           |
|---------|-----------------|
| Status  | Proposed        |
| Date    | 2026-06-08      |
| Authors | Roman Mednitzer |

## Context

A deep review read the execution core, the actuation adapters, the store, the
audit and evidence layer, the transport and SSRF guard, the trifecta context, the
tool surface, and the governance spine (ADRs, STPA, backlog, compliance map). It
used three parallel static sweeps (governance traceability; supply-chain, CI, and
deploy; untrusted-input subsystems) cross-checked against a direct read of every
security-relevant module. Nothing was modified during the review; this ADR records
findings and proposes a remediation wave for ratification, in the manner of
ADR-0011 (external audit) and ADR-0012 (internal audit).

The review confirms the spine is sound and largely as advertised. The SQLite store
enforces append-only and one-active-fact at the storage layer (triggers plus the
partial unique index), parameterised everywhere; no `eval`, `exec`, `pickle`, or
`yaml.load` exists; subprocess calls are list-argv with `shell=False`; the SSH
target is option-injection-guarded; untrusted skill bundles load inert
(`allow_contract=False` is forced); the audit record stores `output_sha256` and
`output_len` only; the per-entry hash chain detects edit, reorder, and
head-truncation; the Merkle tree is RFC 6962 correct and `verify_evidence` is
fail-closed; the SSRF filter correctly blocks IPv4-mapped IPv6, NAT64, and the
decimal, hex, and octal IP encodings. All nine invariants have a proving test.

The review also found that four load-bearing properties are weaker in the running
server than the design states. The two architectural ones drive this ADR:

- The human-approval gate is not bound to a human. The confirmation token is a
  deterministic function of the request (`APPROVE-{action_id}` at T2,
  `CONFIRM-{target}` at T3) and is returned to the caller in the `DRY_RUN`
  response, so an autonomous caller (the agentic operator this product targets)
  can read the token and re-submit to satisfy its own approval. Invariant 6 and
  the trifecta containment of invariant 8 rest on this gate.
- Tier authority is a denylist over a caller-supplied command string, and
  free-form shell actuation (`act_shell` via the SSH adapter) carries
  `base_tier=T1`. The round-up rule (SEC-3) only ever raises the tier on a pattern
  match; an unmatched destructive command (for example `find / -delete`, `nft
  flush ruleset`, `iptables -F`, `>> ~/.ssh/authorized_keys`, a reverse shell, a
  Windows `Remove-Item -Recurse -Force`) stays at the T1 floor and executes with
  no human approval.

The remaining two are latent-control and audit-completeness gaps: several declared
safety controls are implemented but never wired into the running server
(`CredentialBroker`, BL-049; `BudgetTracker`; the kill switch has no operator
actuator; runtime Merkle and RFC 3161 anchoring is never invoked and the real TSA
raises `NotImplementedError`), and the state-changing `ingest_observation` tool
writes facts and arms the trifecta latch yet bypasses `run()`, so it is unaudited
and absent from the UCA table.

## Decision

1. Adopt this review as the next audit wave after ADR-0012, recorded with Status
   Proposed pending operator ratification. Confirmed-correct controls are not
   reopened.
2. Accept the findings as backlog items BL-072 to BL-090, each mapped to a
   security constraint or invariant and citing this ADR.
3. Ratify two architectural changes, each refining an existing decision additively
   (the L1 signatures extend, they do not break):
   a. The approval gate becomes a challenge-response. A `DRY_RUN` mints a
      server-issued, single-use nonce bound to `action_id`, `target`, `tier`, and
      `PATTERNS_VERSION`, with a short TTL, held in server state and surfaced to
      the operator through a channel the model does not control (the server
      console or a separate confirm step), not echoed in the tool result. The real
      run requires that nonce. This extends ADR-0005 Decision 5 and SEC-2; it
      prevents UCA-20 and UCA-22 against an automated caller (BL-072).
   b. Free-form shell, runbook, and any future arbitrary-exec actuation has a
      minimum tier of T2 (human-gated). The content denylist and round-up may only
      raise a tier, never certify an unmatched command as safe; `SSHAdapter`
      moves `base_tier` from T1 to T2 (or the command is constrained to a vetted
      catalogue). This refines ADR-0004 Decision 2 and SEC-3 (BL-073).
4. Wire the latent controls or document their non-delivery in `LIMITATIONS.md`
   with a date: `CredentialBroker` into the actuation path (BL-049),
   `BudgetTracker` into `run()` (BL-074), an operator actuator and durable trip
   record for the kill switch (BL-075), and runtime checkpointing plus a
   non-forgeable stamper for the audit evidence (BL-076). Remove or wire the dead
   `ExecutionRequest.untrusted` field (BL-083).
5. Close the governance traceability gaps: add a UCA row and SEC coverage for
   `ingest_observation` (BL-085); add SEC "Prevents" coverage for UCA-4 to UCA-7
   (`act_ansible`, `act_opentofu`), UCA-10 (`act_talos` destructive), UCA-12 and
   UCA-13 (`act_redfish`), and UCA-23 (`set_mode`), and mark the unimplemented
   `act_cloud` and `act_redfish` rows planned (BL-089); annotate the aspirational
   compliance-map rows with their tracking item (BL-090).
6. Correct documentation that over-states a delivered guarantee through appended
   audit notes (ADRs are immutable): ADR-0004 (the denylist raises tier; it is not
   a completeness guarantee for free-form commands), ADR-0005 (in v0 the read
   tools and `ingest_observation` bypass `run()`), and ADR-0008 (the runtime
   produces no Merkle or RFC 3161 anchor; the live trail is a keyless hash chain
   plus the operating-system append-only control, and the real TSA is not built).

### Findings

Verification: R = reproduced by executing the code, V = verified against the exact
source, S = static review (credible, not independently executed).

Severity: P1 = a load-bearing invariant or control is defeated or unenforced in a
reachable path, fix before the agentic or HTTP surface is relied on; P2 = a real
weakness or hardening gap with a bounded or not-yet-wired blast radius; P3 =
cosmetic, documentation, or defense in depth for a path not currently reached. P1
corresponds to the Critical and High bands used in ADR-0012, P2 to Medium.

| BL | Finding | Constraint | Sev | Verify | Status |
|----|---------|-----------|-----|--------|--------|
| 072 | Approval gate is not human-binding: `expected_token` is a deterministic function of the request and is returned in the `DRY_RUN` body, so an autonomous caller self-approves T2 and T3 | SEC-2, INV 6, 8 | P1 | V | open |
| 073 | Free-form shell actuation runs unmatched destructive commands at T1 with no approval (`SSHAdapter.base_tier=T1`; denylist is upgrade-only); classifier misses `find -delete`, `iptables -F`, `nft flush ruleset`, `kubectl drain/cordon`, mass `DELETE`/`UPDATE`, Windows `Remove-Item -Recurse`/`Format-Volume`/`Stop-Computer` | SEC-3, INV 2, 6 | P1 | V | open |
| 074 | `BudgetTracker` is defined but never wired into `run()`; no per-session action, cost, or wall-time ceiling is enforced on the execution path | SEC-8, INV 9 | P2 | V | open |
| 075 | The kill switch is checked on every call but has no operator actuator (no MCP tool, no signal handler, no file sentinel); only the unwired `CredentialBroker.kill_all` trips it, and the trip state is non-durable | SEC-8, INV 9 | P2 | V | open |
| 076 | Runtime audit anchoring is absent: `make_checkpoint`, `merkle_root`, and the stampers are never invoked by the server; `LocalStamper` is keyless and forgeable; `Rfc3161Stamper` raises `NotImplementedError`. The live trail is a keyless hash chain plus operating-system append-only only | SEC-9, INV 3 | P2 | V | open |
| 077 | `redact_args` recurses with no depth or size bound and runs before the runner's `try`, so a deeply nested args payload raises out of `run()` with no audit record (DoS plus audit-completeness gap) | SEC-2, INV 1 | P2 | V | open |
| 078 | `execution/audit.py::_canonical` lacks `default=str`, so `AuditLogger.record` raises on a non-JSON-native arg value, breaking the documented logger-never-raises property (not reachable through the currently wired tools; defense in depth for the invariant) | SEC-8, INV 3 | P3 | V | open |
| 079 | The SQLite store file and its WAL and SHM sidecars are created with the default umask, not `0o600`; restricted or sensitive facts may be group or world readable (the audit log already does this, BL-064) | SEC-9 | P2 | V | open |
| 080 | `scrubbed_env` copies the full server environment into every wrapped actuation subprocess, exposing unrelated secrets (`PRAXIS_HTTP_TOKEN`, `STORE_DSN`, a Vault token) to ansible, tofu, runbooks, talosctl, and their plugins | INV 9 | P2 | V | open |
| 081 | The Ansible adapter interpolates `host.name` into `--limit` and `action` as the playbook path without validation; `host="all,!localhost"` widens blast radius and a path or URL `action` escapes a playbook root (runbook has the same path gap, BL-024) | SEC-5 | P2 | V | open |
| 082 | The talosctl verb allowlist (BL-048) gates only `parts[0]`; later tokens are appended raw, so an allowed verb can carry an injected flag (`get --talosconfig /evil`), and `nodes`/`endpoints` values are unvalidated (residual of BL-047, BL-048) | SEC-5, SEC-8 | P2 | V | open |
| 083 | Trifecta containment lives only in the `run_action` handler, not in `run()`; `ExecutionRequest.untrusted` is dead; the untrusted latch arms only on live collection (`collect.py`), not on reading already-stored untrusted facts in a fresh session | SEC-4, INV 8 | P2 | V | open |
| 084 | The trifecta `guard_actuation` for T2 and above is passed `approved = (token is not None)` (presence, not validity), so a T2-plus call with a bad token in an untrusted session is audited as gated although the executor later denies | SEC-4, INV 8 | P2 | V | open |
| 085 | `ingest_observation` is `read_only=False` (writes facts, arms the trifecta latch) yet bypasses `run()` and is absent from the UCA table, so untrusted-driven state writes leave no audit record and no STPA control (sharpens BL-017, BL-062) | SEC-2, INV 1 | P1 | V | open |
| 086 | The Helm chart renders `storeDsn` (a PostgreSQL DSN with the password) as a plaintext Deployment env value; it lands in etcd and `helm history`, readable by anyone with `get` on the namespace. The http token already uses `secretKeyRef`; the DSN must too | SEC-9 | P1 | V | open |
| 087 | Deploy hardening below bar: systemd drop-in missing `PrivateUsers`, `ProcSubset=pid`, `RemoveIPC`, `IPAddressDeny`/`SocketBindDeny`; base unit duplicates the drop-in (partial-deploy hazard); Helm NetworkPolicy DNS egress uses `namespaceSelector: {}` and CIDR blocks lack an RFC1918 and IMDS `except`; `runtimeClassName` default is empty | SEC-7 | P2 | S | open |
| 088 | Supply-chain hygiene: the fuzz job runs Python 3.14 (pre-release); `ruff`/`mypy`/`pytest`, `psycopg[binary]`, and `hatchling` carry no version bounds; CI pip-installs without a hash-locked file; the SBOM enumerates the environment (with dev tools), not the production dependency graph | governance | P2 | S | open |
| 089 | STPA coverage gaps: UCA-4 to UCA-7, UCA-10, UCA-12, UCA-13, and UCA-23 appear in no SEC "Prevents" column; `act_cloud` and `act_redfish` have no adapter and are not marked planned; `set_mode` escalation has no test | governance | P2 | V | open |
| 090 | Compliance-map rows assert latent controls as delivered (NIS2 Art. 21 to `CredentialBroker`, BL-049; CRA Annex I to the default-deny NetworkPolicy ingress, BL-051, and to a digest-pinned image, placeholder sha256, BL-033); annotate each with its tracking item | governance | P3 | V | open |

BL-017, BL-024, BL-046, BL-049, BL-050, BL-051, BL-062, and BL-068 are already
open and are confirmed by this review; they are referenced above, not duplicated.

## Consequences

Positive: the two properties the product most depends on (a human gate the model
cannot satisfy, and a tier floor for arbitrary execution) are stated as ratifiable
decisions with tests to follow; the latent controls and the audit-anchoring gap
are tracked with a verification level, so the backlog reflects evidence, not
conjecture; the governance tables regain end-to-end traceability.

Negative: the backlog grows by nineteen items; BL-072, BL-073, BL-076, and the
credential and budget wiring are architectural and need their own changes; the
approval-nonce change touches the operator workflow (a `DRY_RUN` no longer hands
back a paste-ready token).

Neutral: this ADR records findings and proposes acceptance; enforcement is the
code and tests under each item. The single-operator manual stdio path, where a
disciplined human reviews each `DRY_RUN` and pastes the token, carries lower
residual risk than the agentic path this ADR is written to protect.

## Alternatives considered and rejected

- Keep the deterministic approval token and rely on the client to gate. Rejected:
  the product is an AI-operations plane; the gate must hold when the caller is the
  model, which a request-derived token cannot do.
- Make the denylist exhaustive instead of flooring free-form shell at T2.
  Rejected: a denylist over a shell string is not completable (indirection,
  encoding, new binaries); a tier floor for arbitrary execution is sound where a
  blocklist is not, and matches the ADR-0004 allow-list-for-capabilities reasoning.
- Fix everything in the change that carries this ADR. Rejected, per ADR-0012: the
  architectural items merit separate, reviewable changes; this ADR proposes and
  tracks them.

## Revisit triggers

- The HTTP transport is implemented (raises BL-072, BL-076, BL-080, and BL-087 in
  urgency, since the caller is then remote and the egress and anchoring paths go
  live).
- An open item here is found exploitable in a wired path before it is scheduled.
- A later review contradicts a recorded verdict (append an audit note, never
  rewrite a resolved row).
