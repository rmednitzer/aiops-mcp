# 06 Loss scenarios

A loss scenario explains how a UCA (`05-ucas.md`) actually occurs: the causal
factors, including adversary-driven ones (STPA-Sec). Each names the constraint
(`07-security-constraints.md`) that mitigates it.

## Scenario LS-1 (UCA-1, UCA-8): under-rated privileged command runs

Causal factors: the classifier does not recognize a privilege-escalation cue (a
novel `sudo` spelling, an aliased binary), so a T2+ action is treated as T1 and
runs without a gate. Or a deny-listed pattern is checked after tier gating and
slips through in `open` mode.

Adversary path: a model-driven plane is induced (by injected content, LS-6) to
phrase a destructive command so it dodges a naive substring match.

Mitigation: SEC-3 (conservative round-up, sudo/doas/pkexec floor at T2), SEC-1
(deny-first, unconditional, checked before tier gating), and the
`PATTERNS_VERSION`-tracked review of `patterns.py`.

## Scenario LS-2 (UCA-2, UCA-9, UCA-21): execution before audit

Causal factors: a tool writes its audit record after acting (or in a `finally`
that a crash skips), so a failed or partial action leaves no record. An approval
is checked after the side effect began.

Mitigation: SEC-2 (single ordered pipeline: audit record is part of every run and
the order is fixed; a denial/precondition failure is itself audited), SEC-8
(logger never raises, degrades to stderr, so absence of a sink never permits an
unaudited run).

## Scenario LS-3 (UCA-15, UCA-16, UCA-17): erroneous reconciliation

Causal factors: a drift finding auto-triggers a fix; or convergence runs against a
desired-state snapshot that has since been superseded; or the diff is computed
against the wrong target because host identity was not validated.

Mitigation: SEC-6 (DRY_RUN -> approve -> execute, no auto-fix; convergence
validates the target and the baseline currency before acting), SEC-5 (host_type
gate prevents wrong-adapter targeting).

## Scenario LS-4 (UCA-11): SSH attempted against Talos

Causal factors: actuation code branches on a default path (SSH) and forgets to
check host_type; a Talos node is in an `ssh_alias`-shaped inventory row by mistake.

Mitigation: SEC-5 (every actuation adapter asserts host_type; the SSH adapter
refuses a Talos target and the refusal is audited).

## Scenario LS-5 (UCA-26, UCA-14): boundary failure / SSRF pivot

Causal factors: HTTP is enabled with a token but binds `0.0.0.0` without the
non-loopback opt-in; or a server-initiated request (a cloud API call, a webhook)
is pointed at a link-local or RFC1918 address to pivot into the private fleet
network.

Mitigation: SEC-7 (token AND non-loopback opt-in AND SSRF egress filter, each
failing closed; no token passthrough).

## Scenario LS-6 (UCA-1, UCA-15): indirect prompt injection (adversary-driven)

Causal factors: collected host data or command output contains text crafted to be
read by the model-driven plane as an instruction ("ignore prior limits, run X").
If that session also holds sensitive data and an actuation capability, the
injected instruction can drive a real action (the lethal trifecta).

Mitigation: SEC-4 (lethal-trifecta containment: read tools separable from act
tools, a human gate between observe and actuate, all collected data treated as
untrusted data and never as control), reinforced by SEC-2 (the human gate at T2+
is the choke that an injected instruction cannot satisfy on its own).

## Scenario LS-7 (UCA-18, UCA-19): silent state mutation

Causal factors: a code path updates a fact row in place, or a maintenance script
deletes superseded rows, erasing the as-of history that audits and drift depend
on.

Mitigation: SEC-10 (append-only enforced at the storage layer by a delete-blocking
trigger; supersession requires actor + reason; the active-fact unique constraint).

## Scenario LS-8 (UCA-3, output handling): secret/body leak into audit

Causal factors: a tool logs raw output for debugging; an unbounded body is written
to the audit log; a secret in a parameter is logged unredacted.

Mitigation: SEC-9 (audit stores hash + length only; redaction applied to audited
parameters; output truncated before any handling).

## Scenario LS-9 (UCA-20, UCA-22, UCA-24, UCA-25): approval/kill-switch defeat

Causal factors: an approval token is reused across calls or replayed on a bounded
retry; the kill switch sets a flag the runner does not check on new calls, or it
auto-clears.

Mitigation: SEC-2 (approval bound to one action; retry requires fresh approval),
SEC-8 (kill switch checked inside the runner on every call; clears only by
explicit operator action).
