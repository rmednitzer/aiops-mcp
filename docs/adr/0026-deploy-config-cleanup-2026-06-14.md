# ADR-0026: Deploy and config cleanup; Helm health probes (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes the BL-060 residuals, from ADR-0012)

## Context

BL-060 bundled several deploy-and-config hygiene items found in the ADR-0012 audit.
Most were closed in later waves: the `PRAXIS_HTTP_HOST` whitespace strip (BL-067),
the `cyclonedx-bom` pin (BL-071), and the systemd base-unit/drop-in de-duplication
plus the `PrivateUsers`/`ProcSubset`/`RemoveIPC` lockdown (BL-087). Two residuals
remained: the Helm chart declared no liveness or readiness probes, and the prose
compliance map cited enforcement modules in a short form whose root was implicit.

The chart targets the http transport (its documented purpose; the working v0 path is
stdio on a workstation, BL-093), and HTTP serving is staged behind the enforced
transport guard (BL-012), so the chart is already marked not-yet-runnable at install
time. Probes complete that staged production posture rather than enabling anything
new today. The MCP surface has no unauthenticated health route (it requires the
bearer token), so an `httpGet` probe is not appropriate.

## Decision

1. Add configurable liveness and readiness probes to the Deployment as a
   `tcpSocket` check on the MCP port (`mcp-http`), tuned by a `probes` block in
   `values.yaml` (`enabled`, `initialDelaySeconds`, `periodSeconds`,
   `timeoutSeconds`, `failureThreshold`). They render only for the http transport
   (`{{- if and .Values.probes.enabled (eq .Values.transport "http") }}`); stdio has
   no listening port, so the probes are omitted there. A `tcpSocket` check is chosen
   over `httpGet` because there is no unauthenticated health endpoint, and over an
   `exec` check because the container is distroless and minimal. Verified with
   `helm lint` and `helm template` (probes present for http, absent for stdio).

2. Normalise the compliance-map path citations by stating the convention once: an
   enforcement path is repo-relative when it begins with a top-level directory or a
   root file, and is otherwise relative to `src/praxis/`; the machine-checked
   `compliance-controls.json` always uses the full repo-relative form. This resolves
   the implicit-root ambiguity surgically, without rewriting every citation, and
   points readers at the validated catalog for the authoritative form.

3. Record the already-closed sub-items (BL-067, BL-071, BL-087) here so BL-060 closes
   with a complete account rather than appearing half-done.

## Consequences

Positive: the chart now declares health probes for its http target, so a future
HTTP-serving deployment gets liveness/readiness without a follow-up; the probes are
off for stdio where they would be meaningless; the compliance-map citations are
unambiguous and point at the validated catalog. The change is verified with helm.

Negative: the probes cannot be exercised end to end until HTTP serving lands
(BL-012), so like the rest of the chart they encode posture ahead of a runnable
server; a `tcpSocket` check confirms the port is open, not that the MCP handshake
works (the strongest check available without an unauthenticated health route).

Neutral: the compliance-map normalisation is a stated convention plus the catalog
cross-reference, not a rewrite of each citation; if a future reviewer prefers fully
expanded paths in the prose, that is a mechanical follow-up.

## Alternatives considered and rejected

- An `httpGet` liveness probe on a `/health` path. Rejected: no unauthenticated
  health route exists, and adding one widens the surface the transport guard exists
  to keep closed.
- Probes that render for every transport. Rejected: stdio has no listening port, so
  a probe there would always fail; gating on the http transport keeps the chart
  correct for both.
- Rewrite every short path citation in the compliance map to the full repo-relative
  form. Rejected for now as a broad cosmetic churn; the stated convention plus the
  validated catalog resolves the ambiguity surgically.

## Revisit triggers

- HTTP serving lands (BL-012): validate the probes against a live server and
  consider an authenticated readiness check richer than `tcpSocket`.
- helm-unittest is added (BL-032): assert the probe rendering (present for http,
  absent for stdio) as a chart test.
