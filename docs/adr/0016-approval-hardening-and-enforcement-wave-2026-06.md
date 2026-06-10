# ADR-0016: Approval hardening and enforcement wave (2026-06)

## Status

Accepted

## Date

2026-06-10

## Authors

praxis maintainers (implementation review wave following ADR-0015)

## Context

ADR-0015 (Status: Proposed) recorded the 2026-06 deep security and architecture
review. It found the spine sound but identified load-bearing controls that the
running server did not enforce as designed, and proposed two architectural
refinements for ratification before implementation:

- Decision 3a: replace the deterministic approval token (`APPROVE-<action_id>`,
  `CONFIRM-<target>`, echoed in the `DRY_RUN` response) with a server-issued,
  single-use, TTL-bound nonce surfaced out-of-band, because an autonomous caller
  could reproduce the deterministic token and self-approve T2/T3 actions
  (BL-072, the P1 finding).
- Decision 3b: floor free-form shell actuation at T2, because the tier patterns
  are a denylist that only rounds up and cannot be complete against arbitrary
  commands (BL-073, P1).

Beyond those two, the review left a cluster of enforcement gaps tracked in the
backlog: the trifecta gate lived in one tool handler rather than the audited
path and keyed partly on token presence (BL-083, BL-084); `ingest_observation`
and the read tools bypassed `run()` (BL-085, BL-017, BL-062); `BudgetTracker`
and `CredentialBroker` were built but unwired (BL-074, BL-049); the kill switch
had no operator actuator and no durable trip (BL-075); and a set of input,
environment, store, audit, and protocol hardening items remained open from the
earlier waves (BL-019, BL-022..BL-026, BL-029, BL-056, BL-068, BL-077..BL-082).

This ADR follows the ADR-0013 precedent: an implementation wave that remediates
a validated cluster of findings in the accompanying change, with a regression
test per fix.

## Decision

1. Ratify ADR-0015 Decision 3a. The approval gate is human-binding by
   construction: a gated `DRY_RUN` through `run()` mints a single-use nonce
   (`secrets.token_urlsafe`) bound to the action id, the target, the tier, and
   the `PATTERNS_VERSION` that classified the action, with a TTL (default 600 s,
   `PRAXIS_APPROVAL_TTL_SECONDS`). The nonce is surfaced ONLY out-of-band via
   `ExecutionContext.approval_sink` (default: the server's stderr, the operator
   console); it never appears in a tool result or in the audit log. The registry
   is in-memory: a restart invalidates every pending nonce (fail closed). The
   deterministic `expected_token` function is removed. For adapters whose
   preview argv differs from the real argv (ansible `--check`, tofu `plan`),
   the request carries an `action_key` (the real-run command) so the minted
   approval binds to the command that will actually execute.

2. Ratify ADR-0015 Decision 3b. `SSHAdapter.base_tier` is raised from T1 to T2:
   free-form remote shell always meets the human gate. The denylist remains
   upgrade-only and gains the missing destructive patterns (`find -delete`,
   `iptables -F`/`--flush`, `nft flush ruleset`, `kubectl drain|cordon|uncordon`,
   SQL `DELETE`/`UPDATE` without `WHERE`, `Remove-Item -Recurse`,
   `Format-Volume`, `Stop-Computer`/`Restart-Computer`, `authorized_keys`
   appends, `ssh-copy-id`). `PATTERNS_VERSION` is bumped to 3.

3. Trifecta containment moves into the single audited path (BL-083, BL-084).
   The session untrusted-content latch is a `SessionTaint` object shared between
   `ServerContext` and `ExecutionContext`; once armed, every T1+ real run through
   `run()` requires a minted approval, validated and consumed in one place,
   before any execution. The handler-level gate (`guard_actuation`,
   `audit_trifecta_denial`, `TrifectaViolation`) is removed: the path it
   approximated is now the path itself, and presence-versus-validity divergence
   is structurally impossible. The latch arms in-path for requests marked
   `untrusted` (the previously dead `ExecutionRequest.untrusted` field is now
   load-bearing), and tool handlers arm it when a read returns observed facts.

4. Every registered tool routes through `run()` (BL-017, BL-062, BL-085).
   `query_facts`, `fact_history`, `drift_scan`, and `ingest_observation` execute
   as the audited path's execute step via a shared `run_audited` helper, so each
   call writes exactly one audit record and is subject to the kill switch and
   budget. The ingest's audit args carry `raw_sha256` and `raw_len`, never the
   raw telemetry body (SEC-9).

5. Latent controls are wired (BL-074, BL-075, BL-049). `ExecutionContext.budget`
   holds an optional `BudgetTracker` (`PRAXIS_MAX_ACTIONS`,
   `PRAXIS_MAX_WALL_SECONDS`): a T1+ real run that has passed every gate charges
   one action immediately before executing and records wall time after, so
   exhaustion is an audited denial and a refused approval can never burn the
   ceiling and lock the operator out. The kill switch
   takes an optional file sentinel (`PRAXIS_KILL_SWITCH_PATH`): a trip writes it,
   the switch reads tripped while it exists (durable across restart, engageable
   by `touch`, removable only out-of-band), and an unreadable sentinel fails
   closed. A new T0 `emergency_stop` MCP tool trips the switch through the
   audited path and is never approval- or budget-gated. `build_context` creates
   a `CredentialBroker` bound to the kill switch; with zero grants enforcement
   is off (the single-operator default), and the first grant flips actuation to
   deny-unless-authorized via a HARD audited precondition.

6. Input, environment, store, audit, and protocol hardening. The classify and
   deny probe includes the tool name, and stdin/env passthrough is documented as
   an unclassified channel that must never be added without classification
   (BL-019). Ansible and runbook actions are confined to configured roots
   (`PRAXIS_PLAYBOOK_ROOT`, `PRAXIS_RUNBOOK_ROOT`), fail closed when unset, and
   the ansible `--limit` host is validated against the shared safe-target
   pattern (BL-024, BL-081). talosctl refuses post-verb option tokens (closing
   the `--talosconfig` and `--recover-skip-hash-check` injections, BL-082 and
   BL-022), validates nodes and endpoints as IP or RFC 1123 names, always passes
   an explicit `--wipe-mode` for reset defaulting to `system-disk` (BL-025), and
   gates a real-run upgrade on a `talosctl health` HARD precondition via a new
   `extra_preconditions` adapter hook (BL-023). The actuation subprocess
   environment is an allowlist (BL-080). `redact_args` is depth-bounded and a
   redaction failure inside `run()` audits-and-denies with placeholder args
   (BL-077). The audit canonicalizer uses `default=str` so the logger cannot
   raise on non-native arg values (BL-078), and appends are serialised under a
   lock (BL-029). The SQLite store file is pre-created `0o600` (BL-079) and seq
   is computed inside the INSERT under a unique index (BL-068). The stdio loop
   bounds the per-line read at 16 MiB with an oversize drain, treats any message
   without an `id` member as a notification that never gets a response, and
   contains deeply nested JSON (BL-056). Collectors parse numerics
   finite-or-default (BL-026).

7. Backlog items BL-017, BL-019, BL-022..BL-026, BL-029, BL-049, BL-056,
   BL-062, BL-068, BL-072..BL-085, and BL-090 are resolved by this wave, each
   with at least one regression test. ADR-0015 remains immutable; its findings
   table statuses are tracked in `docs/backlog.md`.

## Consequences

Positive:

- The P1 self-approval flaw is closed: an autonomous caller that sees only the
  MCP channel cannot mint, derive, or replay an approval. Approval is once again
  a human action, with TTL, single use, and binding to action, target, tier, and
  ruleset version.
- Invariant 1 is now literally true: every registered tool, read or write,
  passes through the one audited path.
- The trifecta gate, budget, kill switch, and credential scope are enforced in
  one place, on the path, instead of approximated per handler or left unwired.
- An unrecognised destructive command over SSH meets the human gate (T2 floor)
  instead of running silently at T1.

Negative:

- Operability cost: every real SSH action now needs a dry run and an approval,
  and the operator must read the token from the server console (stderr), not
  from the tool response. This is the intended cost of a human gate.
- Approvals do not survive a restart, and a nonce burned by a refused
  precondition (for example a failing health pre-flight) requires a fresh dry
  run.
- Ansible and runbook actuation refuse outright until the operator configures
  the confinement roots: a new mandatory deployment step.

Neutral:

- `PATTERNS_VERSION` 3 stamps the new ruleset in every audit record.
- The MCP tool surface grows by `emergency_stop` and `run_action` gains a
  structured `wipe_mode` parameter; the schemas are regenerated.
- The approval flow tests moved from deterministic-token construction to
  sink-captured mint, which is also the documented operator flow.

## Alternatives considered and rejected

- Echo the minted nonce in the `DRY_RUN` response for operability. Rejected:
  the response is exactly the channel an autonomous caller reads; an in-band
  nonce reproduces the BL-072 flaw with extra steps.
- Persist pending approvals across restarts. Rejected: a restart is a security
  boundary; fail closed and re-mint is simpler and safer than a durable token
  store that itself becomes a target.
- Keep the handler-level trifecta gate alongside the in-path gate (defense in
  depth). Rejected: two gates mean two denial records and two divergent
  policies; the lesson of BL-084 is that a gate beside the path drifts from the
  path.
- A separate per-tool audit decorator for the read tools instead of routing
  through `run()`. Rejected by ADR-0005's standing decision: a decorator is
  opt-in and forgettable; one mandatory entry point is not.
- Floor SSH at T3. Rejected: T3 is reserved for irreversible operations with
  one-target-at-a-time semantics; T2 already imposes the human gate without
  collapsing the tier distinction.

## Revisit triggers

- An MCP elicitation or interactive-approval primitive becomes available in the
  protocol version praxis targets, allowing the approval prompt to move from
  stderr to a first-class operator channel.
- Multi-operator deployment: per-operator approval identity and broker grants
  (currently single-operator, in-process) need an authorization model.
- The pending-approval registry needs persistence or cross-process sharing
  (for example an HTTP transport with multiple workers).
- A wrapped tool genuinely requires stdin or environment passthrough, which
  must first extend the classification probe (the BL-019 rule).
