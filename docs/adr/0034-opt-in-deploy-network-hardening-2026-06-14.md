# ADR-0034: Opt-in deploy network hardening (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes the BL-036 namespace-NetworkPolicy element and the BL-087 residual)

## Context

Two deploy-hardening controls were deliberately deferred in earlier waves because a
deny-all default would brick a working install:

- A namespace-wide default-deny `NetworkPolicy` (BL-036). The chart already ships a
  pod-scoped default-deny policy (BL-051), but not a namespace baseline that denies
  every pod by default. A namespace baseline is stronger, but applied unconditionally
  it can cut off co-tenant workloads that share the namespace.
- An IP-level systemd lockdown (`IPAddressDeny`/`IPAddressAllow` + `SocketBindDeny`)
  and a sandbox `runtimeClassName` (BL-087). praxis must reach the operator's fleet
  over SSH/API to actuate, so a blanket `IPAddressDeny=any` without a correct
  allowlist breaks actuation; a `runtimeClassName` that the cluster has not installed
  fails scheduling.

Both were left documented but "operator-scoped" (ADR-0015, ADR-0020). The remaining
work is to make them turnkey opt-ins, default off, so an operator can adopt them
deliberately without the chart imposing a posture that bricks their environment.

## Decision

1. Namespace default-deny is an opt-in Helm value: `networkPolicy.namespaceDefaultDeny`
   (default `false`). When true, the chart renders an additional `NetworkPolicy` with
   an empty `podSelector` (selects every pod in the namespace) and `policyTypes:
   [Ingress, Egress]` with no allow-rules, the canonical deny-all baseline. Because
   NetworkPolicies are additive, the praxis pod keeps its own specific allows; the
   baseline only denies pods that have no policy of their own. Off by default so it
   cannot brick a co-tenant; enable only in a namespace praxis owns.

2. The systemd IP lockdown ships as a turnkey example drop-in,
   `deploy/systemd/praxis.service.d/network-lockdown.conf.example`, not as a preset.
   The operator copies it to `network-lockdown.conf`, scopes `IPAddressAllow` to their
   fleet, and reloads. It is a deny-all-then-allowlist (`IPAddressDeny=any` +
   `IPAddressAllow` + `SocketBindDeny=any`). It stays opt-in because a wrong or empty
   allowlist bricks actuation; the base `hardening.conf` points to it.

3. `runtimeClassName` stays the existing optional Helm value (default `""` renders
   nothing), now with regression tests asserting it is absent by default and wired
   through when set.

4. Never weaken a default. All three are off unless the operator turns them on; the
   default install posture is unchanged. The opt-ins are covered by helm-unittest
   assertions (the namespace policy is absent by default and a correct deny-all when
   enabled; `runtimeClassName` absent by default, present when set).

## Consequences

Positive: an operator who owns the namespace can adopt a stronger
deny-everything-by-default network baseline and an IP-level host lockdown with
turnkey, tested artifacts, instead of hand-rolling them. The default install is
unchanged, so nothing is bricked out of the box. BL-036's namespace element and
BL-087's residual are closed.

Negative: the controls are off by default, so the stronger posture is only in force
when the operator opts in; the chart cannot guarantee it. The systemd lockdown's
correctness depends on the operator's allowlist, which the unit cannot validate.

Neutral: the namespace default-deny is a separate `NetworkPolicy` document in the
same template, gated on `networkPolicy.enabled` as well, so disabling NetworkPolicies
disables both. The IP lockdown is shipped as `.example` so it is never auto-loaded by
`systemctl daemon-reload` until the operator renames it.

## Alternatives considered and rejected

- Preset the namespace default-deny (on by default). Rejected: it denies every
  co-tenant pod that lacks its own policy, bricking shared-namespace workloads; the
  chart cannot know it owns the namespace.
- Preset `IPAddressDeny=any` with a placeholder allowlist. Rejected: an empty or
  placeholder allowlist bricks SSH/API actuation on first start; a deny-all host
  network default is the operator's risk decision, not the package's.
- Ship the systemd lockdown as an active `.conf`. Rejected: `daemon-reload` would
  load it immediately; `.example` keeps it inert until the operator opts in.

## Revisit triggers

- The HTTP transport lands (BL-012): revisit `SocketBindDeny` (praxis would then
  listen) and the namespace policy's ingress shape.
- A future multi-tenant deployment mode wants the namespace baseline on by default
  in a praxis-owned namespace (a new chart profile, not a changed default).
