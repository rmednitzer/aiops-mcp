# ADR-0031: Opt-in client-side-only talosctl pre-upgrade health probe (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (implements BL-102, raised for operator decision in ADR-0021)

## Context

A real-run `talosctl upgrade` (and `upgrade-k8s`) is gated on a HARD pre-flight
`talosctl health` precondition (BL-023, SEC-5): if the cluster is not healthy, the
upgrade is refused as an audited HARD violation. The probe is built in
`src/praxis/actuation/talosctl.py::_health_ok` and runs `talosctl --nodes ...
--endpoints ... health`.

`talosctl health` defaults to a server-side check (`--server=true`): the API server
runs the health assertions across the cluster. On a freshly bootstrapped or
single-node cluster, or one whose discovery service is not fully converged, those
server-side checks can fail for reasons unrelated to upgrade readiness, so the HARD
gate can spuriously block a legitimate upgrade. `talosctl health --server=false` runs
only the client-side checks, which avoids that class of false negative at the cost of
a less comprehensive check.

BL-102 (from the ADR-0021 audit) flagged this as a change to a HARD safety
precondition (SEC-5) and explicitly deferred it to an operator decision rather than
changing it unilaterally. The operator has now chosen to add the capability.

## Decision

1. Add an additive, opt-in `health_client_side_only` boolean param (default `False`).
   When truthy, `_health_ok` appends `--server=false` to the health argv, so only the
   client-side checks run. The default is unchanged: the full server-side check.

2. Never weaken the default and never skip the gate. The health precondition stays
   HARD and always runs for a real-run upgrade; the flag narrows its scope, it does
   not remove it. There is no value of the flag that bypasses the health check.

3. Fail closed on a malformed flag. The value is coerced by `_as_health_flag` inside
   the health predicate's `test`, so a non-boolean is a HARD audited refusal (a
   throwing predicate is a HARD failure), never a silent relaxation of the gate.

4. Keep it audited and operator-driven. The flag is a structured param on the
   `run_action` tool (`health_client_side_only`), so it is part of the request args
   written to the tamper-evident audit record and shown in the DRY_RUN preview the
   operator approves out-of-band. An autonomous caller cannot use it to dodge the
   gate: the gate still runs (client-side), and the upgrade still needs the minted
   T2/T3 approval.

## Consequences

Positive: an operator can complete a legitimate upgrade on a post-bootstrap cluster
whose server-side health checks spuriously fail, without disabling the safety gate.
The capability is additive, opt-in, fail-closed, and audited; the default posture is
unchanged.

Negative: a client-side-only check is less comprehensive than the server-side check,
so when the operator opts in they accept a weaker (but non-empty) pre-upgrade
assurance. This is a deliberate, audited operator choice, visible in the DRY_RUN and
the audit trail, not a default.

Neutral: the flag maps directly to the talosctl `--server` flag, so its semantics
track the tool. It is set as a single `--server=false` token (not a separated value),
consistent with the adapter's structured-argv, no-free-form-options posture (BL-082).

## Alternatives considered and rejected

- Always pass `--server=false`. Rejected: it weakens the default health gate for every
  upgrade to avoid an occasional false negative, contrary to the never-weaken-a-default
  rule.
- Make the health precondition SOFT (a warning) when server-side fails. Rejected: it
  silently downgrades a HARD safety control and an autonomous caller could proceed past
  an unhealthy cluster.
- Leave BL-023 unchanged and require the operator to run the upgrade outside praxis when
  server-side health is spuriously red. Rejected: it pushes a privileged action off the
  audited path, losing the audit record and the approval gate.

## Revisit triggers

- talosctl changes the `--server` flag semantics or default, or splits client/server
  health into a different interface.
- A SOFT-with-explicit-acknowledgement design is wanted (record the spurious
  server-side failure as a finding, then allow client-side-only) once a structured
  finding surface exists for pre-flight checks.
