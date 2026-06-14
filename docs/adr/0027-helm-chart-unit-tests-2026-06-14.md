# ADR-0027: Helm chart unit tests gated in CI (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes BL-032, from ADR-0011)

## Context

The Helm chart encodes load-bearing security posture: PSA-restricted pod and
container `securityContext`, a default-deny NetworkPolicy (BL-051, BL-087), a
ServiceAccount that never mounts an API token (invariant 9), a digest-pinned image
(ADR-0001), secret material sourced only through a `secretKeyRef` with the inline DSN
refused (BL-086), and the http-gated health probes just added (ADR-0026). None of
this was machine-verified. `helm lint` checks chart structure, not rendered values,
so a regression that dropped `readOnlyRootFilesystem`, rendered probes for the stdio
transport, inlined a secret, or relaxed the default-deny ingress would pass CI
silently.

BL-032 (from the ADR-0011 external audit) asks for helm-unittest chart assertions
gated in CI; ADR-0026's revisit trigger named this item explicitly as the place to
assert the probe rendering.

## Decision

1. Adopt helm-unittest (the `helm-unittest/helm-unittest` plugin) for render-time
   chart assertions. Three suites under `deploy/helm/praxis/tests/` cover:
   - `deployment_test.yaml`: the PSA-restricted pod and container `securityContext`,
     `automountServiceAccountToken: false`, digest-pinning (and the helpers `required`
     refusal of an empty digest), the `secretKeyRef`-only http token and store DSN,
     the BL-086 inline-`storeDsn` refusal, the `http.allowAny` opt-in env gating, and
     the http-gated `tcpSocket` probes (present for http, absent for stdio and when
     `probes.enabled` is false) per ADR-0026's trigger.
   - `networkpolicy_test.yaml`: ingress omitted when no peer is named (the canonical
     deny-all shape, BL-051), DNS-only egress to `kube-system`, the always-on
     `169.254.0.0/16` excision and operator-`except` merge (BL-087), and the
     `failedTemplate` refusals for the bare-string and missing-`cidr` egress shapes.
   - `serviceaccount_test.yaml`: the ServiceAccount token-automount-off invariant and
     the ClusterIP service port.

2. Gate it in CI as a pinned `helm-test` job in `ci.yml` (`azure/setup-helm` by
   commit SHA, helm `v3.21.0`, the plugin at `v1.1.1`, matching the repo's SHA-pin
   posture) and add it to the `ci-success` aggregate's `needs`, so branch protection's
   single required check now also requires the chart tests with no new
   branch-protection rule. Add a `make helm-test` target for local parity and keep the
   suites out of the packaged chart via `.helmignore`.

Choosing the assertions: prefer explicit `equal`/`contains`/`notExists` on the
rendered security and gating fields over snapshots, so a failure names the regressed
field; use `failedTemplate.errorPattern` (substring) for the deliberate `fail` guards
so a future message reword does not break the test while the meaningful prefix is
still asserted.

## Consequences

Positive: the chart's security posture and the http-gated probes are machine-verified
on every PR; a change that weakened a `securityContext` field, shipped probes for
stdio, inlined a secret, or relaxed the default-deny NetworkPolicy fails the required
gate. Folding the job into `ci-success` makes it required through the existing
branch-protection check (an in-aggregate pattern BL-052 can reuse). The suites run
from source, so `.helmignore` keeps the package clean.

Negative: helm-unittest renders templates; it does not run against a live cluster, so
it verifies rendering, not admission or runtime behavior (a correctly rendered
`tcpSocket` probe still cannot be exercised until HTTP serving lands, BL-012). The
pinned helm and plugin versions need maintenance (Renovate) to stay current.

Neutral: the plugin is a CI and developer dependency only, not a runtime or
packaged-chart dependency, so it does not touch the execution core's dependency-free
posture (ADR-0014). BL-052 (making codeql/fuzz/sbom/dependency-review required) is
unchanged; this only demonstrates the in-aggregate gating approach for the chart job.

## Alternatives considered and rejected

- `helm template` piped to a policy engine (conftest/OPA Rego, or a Kyverno test).
  Rejected: a second policy language and toolchain for what are straightforward
  render-value assertions; helm-unittest keeps the assertions in YAML beside the
  chart. Conftest or Kyverno remain the right tool if cluster-admission policy is
  later wanted.
- Snapshot tests (helm-unittest `matchSnapshot`) as the primary mechanism. Rejected:
  a snapshot blob obscures which field regressed and invites a blind
  `--update-snapshot`; explicit field assertions document intent and fail legibly.
- terratest or a Go test harness. Rejected: it pulls a Go toolchain into a Python
  repo for render-time checks that YAML assertions already cover.
- A separate `helm-test.yml` workflow required via branch protection (like codeql).
  Rejected: BL-052 notes branch protection is external to the repo; folding the job
  into `ci-success` makes it required through the check that is already configured.

## Revisit triggers

- HTTP serving lands (BL-012): add assertions or an integration test that exercise the
  probe endpoint and any authenticated readiness route against a live server.
- A `values.schema.json` is added: enable `--strict` and assert schema-validation
  failures for out-of-range values.
- BL-052 is taken up: consider the same in-aggregate pattern (or a documented
  branch-protection set) for codeql/fuzz/sbom/dependency-review.
