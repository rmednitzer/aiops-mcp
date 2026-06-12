# ADR-0020: Test/fuzz expansion and deploy hardening wave (2026-06-12)

## Status

Accepted

## Date

2026-06-12

## Authors

praxis maintainers (third remediation wave of 2026-06-12, following ADR-0019)

## Context

Two backlog clusters remained that are verifiable self-contained: BL-061 (a
test/fuzz expansion across the untrusted-input surfaces) and the implementable
part of BL-087 (deploy hardening). This wave does both. BL-061 was also a
deliberate adversarial pass: an SSRF bypass sweep run as code (not just new
tests) against the actual filter, to find gaps rather than only document the
controls that already hold.

## Decision

1. SSRF bypass sweep (BL-061) and one real fix (BL-096). An empirical probe ran
   the filter against IPv4-embedded-in-IPv6 forms (v4-mapped `::ffff:0:0/96`,
   NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) of loopback, RFC1918, and the IMDS
   address; IPv6 ULA/multicast/unspecified; URL userinfo masking
   (`http://8.8.8.8@127.0.0.1/`); and bracketed v6 literals. All were already
   blocked except the deprecated 6to4 relay anycast `192.88.99.0/24` (RFC 7526),
   which `ipaddress` classifies inconsistently across patch versions. It is now
   blocked with an explicit deterministic network constant, and the sweep is a
   regression test. No over-blocking: public v4/v6 literals (including their
   bracketed and decimal forms) still pass.

2. Host_type refusal matrix (BL-061). A parametrized test asserts that every
   actuation adapter refuses every host_type outside its declared support set,
   as an audited HARD precondition decided before any argv is built (SEC-5,
   invariant 5): 5 adapters times 4 host types, with the supported combinations
   skipped (they are covered by the adapter-specific tests). This pins the
   refusal half of the gate as a complete matrix rather than per-adapter spot
   checks.

3. Backend parity suite (BL-061). Seven shared bitemporal behaviors (roundtrip
   provenance, supersede-on-put, supersede provenance and the original row's
   survival, the actor/reason requirements, active-fact filtering, and edge
   re-put semantics) run against SQLite always and Postgres when
   `PRAXIS_TEST_PG_DSN` names a live database, through the `StoreProtocol`. The
   two backends cannot now drift apart on the semantics the model relies on;
   backend-specific mechanics (file modes, trigger text, seq internals) stay in
   their per-backend modules. Verified against a live PostgreSQL 16.13.

4. Fuzz surface expansion (BL-061). `scripts/fuzz.py` gains three stages beside
   the classify/policy/redaction loop: the SKILL.md frontmatter parser (never
   raises, returns a `(dict, str)`), the RFC 6962 Merkle tree (never raises,
   deterministic across a re-run, single-leaf root is the domain-separated leaf
   hash and never the bare content hash), and `verify_evidence` (never raises;
   garbage checkpoints are `ok=False`, fail-closed). The nightly run exercises
   the untrusted-input surfaces the audit named, not only the command surfaces.

5. Deploy hardening (BL-087, partial). The systemd drop-in adds `PrivateUsers`,
   `ProcSubset=pid`, and `RemoveIPC`, and is de-duplicated against the base unit
   (the baseline controls stay in `praxis.service` so an install without the
   drop-in is still protected; the drop-in no longer repeats them). The Helm
   NetworkPolicy scopes DNS egress to the `kube-system` namespace by its
   API-managed `kubernetes.io/metadata.name` label (unspoofable), and
   `networkPolicy.egressCIDRs` becomes a list of `{cidr, except}` objects that
   always excise `169.254.0.0/16` (cloud metadata and link-local) plus any
   operator-supplied sub-ranges; the legacy bare-string form is refused at
   render time with a migration message.

6. The residual of BL-087 stays open and is documented, not silently dropped:
   `IPAddressDeny`/`SocketBindDeny` and a sandbox `runtimeClassName` are written
   into the drop-in as commented, operator-scoped controls, because a deny-all
   default would brick SSH actuation to the operator's fleet ranges, which the
   chart cannot know. BL-061 and BL-096 are resolved; BL-087 is advanced with
   its residual annotated.

## Consequences

Positive:

- The audit's "test/fuzz expansion" item is delivered as breadth that would have
  caught real regressions: the SSRF sweep found and closed an actual gap, and the
  parity suite makes a backend divergence a red test rather than a production
  surprise.
- The host_type matrix and the fuzz stages turn three more untrusted-input
  surfaces from "has some tests" into "swept".
- A from-scratch `helm install` is now private by default at both ingress and
  egress, and a systemd install scores materially better on
  `systemd-analyze security`.

Negative:

- `networkPolicy.egressCIDRs` is a breaking values change (strings to objects);
  the render-time `fail` makes the migration explicit but it is still a manual
  edit on upgrade.
- `PrivateUsers=true` remaps UIDs and can interfere with host-path access that
  needs a real UID; praxis writes only under `StateDirectory`, so it is safe
  here, but an operator adding host mounts must re-check it.
- The parity suite roughly doubles the store test count on the Postgres lane;
  on the SQLite-only default lane the Postgres half skips.

Neutral:

- No runtime code path changes except the one SSRF constant; the deploy changes
  are manifests and the test changes are additive.
- `192.88.99.0/24` is deprecated address space; blocking it has no legitimate
  cost.

## Alternatives considered and rejected

- Rely on `ipaddress.is_global`/`is_reserved` for the 6to4 relay range instead
  of an explicit constant. Rejected: the classification of `192.88.99.0/24`
  varies across CPython patch releases (the probe showed it), so a deterministic
  constant is the only stable control; this mirrors the existing explicit CGNAT
  constant.
- Default `IPAddressAllow` to the RFC1918 ranges. Rejected: praxis's fleet is
  operator-specific and frequently not RFC1918 (Tailscale CGNAT, public IPs); a
  wrong guess is worse than a documented, commented opt-in.
- Keep `egressCIDRs` as strings and append the `except` in the template only.
  Rejected: the operator cannot then add their own sub-range exceptions, and the
  object form is where per-range `except` belongs.
- Fold the SSRF fix into a future "resolving SSRF" item (BL-046). Rejected:
  BL-046 is about hostname resolution and rebinding; the 6to4 gap is a literal
  classification gap that belongs with the bypass sweep that found it.

## Revisit triggers

- BL-046 (hostname-resolving, rebinding-aware SSRF) lands and wires the filter
  into a real egress path: re-run the bypass sweep against the resolving path.
- The HTTP transport (BL-012) gives the NetworkPolicy ingress a real client to
  scope `ingressFrom` against in a test (helm-unittest, BL-032).
- A Kubernetes release changes the `kubernetes.io/metadata.name` guarantee, or
  the chart's `kubeVersion` floor drops below 1.21.
- `IPAddressDeny`/`SocketBindDeny` become presettable once a standard fleet
  egress range is known (for example a fixed Tailscale CGNAT block), closing the
  BL-087 residual.
