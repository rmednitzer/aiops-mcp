# ADR-0013: Third audit wave (2026-06): actuation, audit, and untrusted-input hardening

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

A third review wave read the full source again, re-ran every gate, and validated
the architecture against established hardening practice for the surfaces praxis
fuses: privileged SSH/subprocess execution (OpenSSH `BatchMode` and host-key
policy, POSIX process groups), append-only audit logging (owner-only file mode,
visible-seam chain resume), untrusted-input parsing (finite-or-default numeric
coercion, frontmatter fence and size discipline), and secret redaction (structural
provider-token anchors, value-complete `Authorization` redaction). The design was
distilled from proven systems and reimplemented natively; this wave closes the gap
between the distilled intent and the delivered code. No third-party code or
cross-repository reference is introduced: praxis stays self-contained (ADR-0001).

The review confirmed the previously-audited controls still hold (the append-only
triggers, the fail-closed evidence verifier, the SSRF numeric-form normalisation,
the deny-first policy). It also confirmed a coherent cluster of open backlog items
from ADR-0011 and ADR-0012 are real and surgically fixable, and surfaced a small
set of new hardening gaps and one self-containment defect:

- The SSH adapter built `["ssh", target, action]` with no host-key policy and no
  `BatchMode`, so it could prompt (and hang a TTY-less MCP call) or accept an
  unverified host key; a leading-dash target was an ssh-option-injection vector.
- The subprocess runner inherited the server environment and stdin, and on timeout
  killed only the direct child: a wrapped tool could read the MCP stdio stream,
  hang on a credential prompt, or leak a grandchild process tree.
- The talosctl adapter enforced the T3 single-target rule on `host.name` rather
  than the actual `host.nodes`, and tokenised a free-form action into argv.
- A trifecta refusal raised out of the tool handler with no audit record.
- The audit logger reopened the file after degrading and dropped the sink to stderr
  on a corrupt tail (losing records); the log was created world/group readable.
- A poisoned embedding (`NaN`) could drag a `NaN` score into vector ranking; the
  manifest parser accepted `----` as a fence, had no size cap, and allowed indented
  and duplicate keys; an empty AIDE report read as a clean host.
- A `context.py` docstring cited an out-of-tree prototype by name as its rationale,
  a self-containment (ADR-0001) and docs-honesty defect.

## Decision

1. Adopt this wave as the third recurring audit (after the external ADR-0011 and the
   internal ADR-0012), validating delivered code against established hardening
   practice and reimplementing every adopted technique natively. No sibling
   repository is named in code or docs; the self-contained invariant is upheld.
2. Remediate the coherent, surgical, security-relevant cluster in the change that
   accompanies this ADR, each fix with a regression test: BL-018, BL-020, BL-021,
   BL-034, BL-047, BL-048, BL-054, BL-055, BL-057, BL-058, BL-059 resolved, plus the
   new items BL-063 to BL-067. Architectural open items (BL-046 SSRF resolution,
   BL-049 credential wiring, BL-051/052 CI/deploy gating) stay open and tracked.
3. Where a resolved item carried a residual beyond the security-critical core, carve
   the residual into a new tracked item rather than over-claim closure: the store
   `seq` cross-connection race (residual of BL-054) becomes BL-068, and the talosctl
   structured-parameter refactor (beyond the BL-048 verb allowlist) is noted as a
   future refinement, not a delivered guarantee.

### Findings

Verification: R = reproduced by executing the code, V = verified against the exact
source.

| BL | Finding | Constraint | Sev | Verify | Status |
|----|---------|-----------|-----|--------|--------|
| 020 | SSH adapter has no host-key policy or `BatchMode`; a leading-dash target is an option-injection vector | SEC-5, INV 5 | High | V | resolved |
| 021 | Subprocess runner inherits stdin (can read the MCP stdio stream) and env (can hang on a prompt), and kills only the direct child on timeout (leaks the process tree) | SEC-8 | High | R | resolved |
| 047 | talosctl T3 single-target rule is enforced on `host.name`, not the `host.nodes` list, so one T3 reset can wipe multiple nodes | SEC-6, INV 6 | High | V | resolved |
| 048 | talosctl tokenises a free-form `action` into argv; constrain the leading verb to an allowlist | SEC-8 | Med | V | resolved |
| 018 | A trifecta refusal raises out of the tool handler with no audit record | SEC-4, INV 3 | Med | R | resolved |
| 055 | Audit logger reopens the file after `_degrade` and drops the sink to stderr on a corrupt tail (losing records) and leaks the handle | SEC-8, INV 3 | Med | R | resolved |
| 057 | Manifest parser accepts `----` as a fence, has no size cap, and allows indented and duplicate keys; non-UTF-8 bytes crash the loader | INV 8 | Med | R | resolved |
| 058 | AIDE empty output reads as a clean host (false negative); collected telemetry has no size cap before parsing | INV 8 | Med | R | resolved |
| 054 | `_cosine`/`similar` propagate a `NaN` from a poisoned or corrupted embedding into the ranking | SEC-10 | Med | R | resolved |
| 034 | `parse_ansible_check` only reads `changed:`; a `FAILED`/`UNREACHABLE` host during a check is dropped | SEC-6 | Med | V | resolved |
| 059 | An `UNEXPECTED` security-predicate finding (a rogue port or user) is ranked `INFO`, below a changed/missing one | SEC-6 | Med | V | resolved |
| 063 | Actuation subprocess does not scrub the env (no `GIT_TERMINAL_PROMPT=0`/`DEBIAN_FRONTEND=noninteractive`) or detach stdin | SEC-8 | Med | R | resolved |
| 064 | Audit log is created world/group readable; not opened `O_APPEND` at the OS level | SEC-9 | Med | R | resolved |
| 065 | Redaction misses common provider token shapes (`github_pat_`, `glpat-`, `npm_`, `AIza`, `ya29.`, Stripe, OpenAI scoped) and stops `Authorization` at the first space, leaking a comma-separated SigV4 signature | SEC-9, INV 3 | Med | R | resolved |
| 066 | `context.py` cites an out-of-tree prototype by name as rationale (self-containment and docs-honesty defect) | governance, INV (self-contained) | Low | V | resolved |
| 067 | `PRAXIS_HTTP_HOST` is not whitespace-stripped, so a `"127.0.0.1\n"` value is misread as non-loopback | SEC-7 | Low | R | resolved |
| 068 | Store `seq` is not unique; the `MAX(seq)+1` read can race across two store instances on one file (residual of BL-054) | SEC-10 | Low | V | open |

## Consequences

Positive: the privileged-execution surface (SSH host-key policy and option-injection
guard, process-group isolation, stdin detachment, env scrubbing, the talosctl verb
allowlist and node-aware T3 gate) is materially hardened with tests; every denial is
now audited; the audit log is owner-only and survives a corrupt tail without losing
records; untrusted parsing (vectors, manifests, AIDE, telemetry size) is robust; and
redaction covers more secret shapes value-completely. The repository is again fully
self-contained in code and docs.

Negative: the actuation subprocess path moved from `subprocess.run` to a `Popen`
plus explicit timeout/kill, which is more code on the trust boundary (covered by a
new timeout test). The talosctl verb allowlist must be extended deliberately when a
new subcommand is needed.

Neutral: this ADR records the wave and its acceptance; enforcement is the code and
tests under each item. The architectural open items from ADR-0012 are unchanged.

## Alternatives considered and rejected

- Resolve every open item from ADR-0011/0012 in one change. Rejected: the
  architectural items (hostname-resolving SSRF, credential wiring, CI/deploy gating)
  are larger than this surgical security cluster and merit their own reviewable
  changes, consistent with ADR-0012's staging.
- Default the SSH host-key policy to `StrictHostKeyChecking=yes`. Rejected for v0:
  a fleet with no pre-seeded `known_hosts` would refuse every first connection;
  `accept-new` (Trust-On-First-Use, refusing a changed key) is the secure default
  and is overridable to `yes` once `known_hosts` is seeded.
- Degrade the audit sink to stderr on a corrupt tail (the prior behaviour).
  Rejected: losing the audit record is worse than a visible seq-reset seam that the
  verifier reports; the seam is the security signal.

## Revisit triggers

- The HTTP transport is implemented (raises BL-046 SSRF resolution and the consent
  registry in urgency).
- A concurrent or multi-instance store path is implemented (raises BL-068).
- A later audit contradicts a recorded verdict here (append an audit note, never
  rewrite a resolved row).
