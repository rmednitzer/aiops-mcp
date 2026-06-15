# Deploy

Hardened deployment artifacts for praxis (BL-014).

## Contents

- `helm/praxis/` a secure-by-default Helm chart:
  - Pod Security Admission `restricted`: `runAsNonRoot`, non-root uid/gid,
    `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities
    dropped, `seccompProfile: RuntimeDefault`.
  - A per-release ServiceAccount with `automountServiceAccountToken: false` (praxis
    needs no Kubernetes API access; invariant 9).
  - A default-deny `NetworkPolicy`: ingress only on the MCP port and only from
    the peers named in `networkPolicy.ingressFrom` (empty default: all ingress
    denied, BL-051); egress only to DNS (scoped to the `kube-system` namespace)
    and explicitly listed fleet CIDRs that always excise 169.254.0.0/16, cloud
    metadata and link-local (the in-cluster complement to the in-process SSRF
    filter, SEC-7; BL-087). Optionally (`networkPolicy.namespaceDefaultDeny`, default
    off) an additive namespace-wide deny-every-pod baseline, for a namespace praxis
    owns (BL-036, ADR-0034).
  - A digest-pinned image (no tags; ADR-0001 supply-chain posture), built from the
    repo `Dockerfile` (BL-092, ADR-0032) and published by the tag-triggered `release`
    workflow with a signed provenance and SBOM attestation (BL-033, ADR-0035). Set
    `image.digest` before installing. (The default `image.digest` is an all-zero
    placeholder that fails closed at pull time until the operator's first release
    populates a real digest; see RELEASE-CHECKLIST.md.)
  - An optional hardened `runtimeClassName` for the code-executing plane (default off;
    BL-087, ADR-0034).
  - `values-prod.yaml`: a production overlay (BL-036) that makes the hardened posture
    explicit and marks the operator-supplied values (the image digest, the NetworkPolicy
    peers and egress) a real deployment must set. It never weakens a default.
- `systemd/praxis.service` plus `praxis.service.d/hardening.conf` for a host
  install. Verify with `systemd-analyze security praxis.service`. An optional
  `praxis.service.d/network-lockdown.conf.example` carries the turnkey IP-level
  lockdown (`IPAddressDeny`/`SocketBindDeny`); copy it to `.conf` and scope the
  allowlist to your fleet to enable (default off; BL-087, ADR-0034).
- `Dockerfile` (repo root): a minimal, non-root, multi-stage build (digest-pinned
  `python:3.12-slim-bookworm` base) that installs the default runtime and runs
  `python -m praxis`. Carries governance-as-code OCI labels. Built and smoke-tested
  in CI by the `image` workflow (never pushed); published to GHCR with signed
  provenance and an SBOM attestation by the tag-triggered `release` workflow, the sole
  publisher. BL-092 (ADR-0032), BL-033 (ADR-0035).
- `zarf.yaml` for an airgap package (chart plus the pinned image).
- `RELEASE-CHECKLIST.md`: the ordered version-bump checklist (gates, image digest,
  chart `version`/`appVersion`, SBOM, tag) so a release never ships an unpinned image
  or a stale SBOM (BL-036).

## Status

The container, Helm, and systemd deployments target the streamable-HTTP transport,
which is opt-in and fails closed without a token and the non-loopback
acknowledgement (ADR-0006). HTTP serving is delivered (ADR-0041) and serves
concurrently (a `ThreadingHTTPServer` over a thread-safe store, ADR-0042); the
default, simplest deployment remains stdio on a workstation (`python -m praxis`).
These manifests encode the production hardening posture for that HTTP transport.

## Known hardening gaps (tracked)

The manifests encode the intended posture; the deep review (ADR-0015) found these
gaps to that bar, each tracked in `docs/backlog.md`. The ADR-0018 wave closed the
`storeDsn` plaintext rendering (now a `secretKeyRef`, with an inline DSN refused at
render time, BL-086) and the unselective ingress (now `networkPolicy.ingressFrom`,
deny-all by default, BL-051). The ADR-0020 wave scoped the DNS egress to
`kube-system`, made `egressCIDRs` `{cidr, except}` objects that always excise
169.254.0.0/16 (cloud metadata and link-local), and added the systemd
`PrivateUsers`/`ProcSubset=pid`/`RemoveIPC` lockdown plus de-duplicated the base
unit against the drop-in (BL-087). These review gaps are now closed:

- The repo `Dockerfile` (BL-092, ADR-0032) builds the referenced image, validated
  in CI by the `image` workflow (build plus a non-root import smoke test), and the
  tag-triggered `release` workflow (BL-033, ADR-0035) publishes it to GHCR with a
  signed SLSA provenance and a CycloneDX SBOM attestation bound to the digest
  (`gh attestation verify`-able). The publish mechanism is complete; the default
  `image.digest` in `values.yaml`/`zarf.yaml` stays an all-zero, fail-closed
  placeholder until the operator cuts the first `v*` release, which records the real
  digest for the operator to pin (RELEASE-CHECKLIST.md). That first-release digest
  population is an operator action, not an open code gap.

The IP-level systemd lockdown (`IPAddressDeny`/`SocketBindDeny`), the sandbox
`runtimeClassName`, and the namespace-wide default-deny NetworkPolicy are now turnkey
opt-ins (default off; BL-087, BL-036, ADR-0034), described under Contents above.

## Quickstart (stdio, no cluster)

```
uv venv --python 3.12 .venv && uv pip install --python .venv -e .
PRAXIS_MODE=guarded .venv/bin/python -m praxis   # speaks MCP JSON-RPC over stdio
```

## Testing the chart

The chart's load-bearing posture (the PSA-restricted `securityContext`, digest
pinning, the `secretKeyRef`-only secret wiring, the http-gated health probes, and the
default-deny `NetworkPolicy`) is asserted with helm-unittest (BL-032, ADR-0027). The
suites live in `helm/praxis/tests/`, run in CI as the required `helm-test` gate, and
run locally with the pinned plugin:

```
helm plugin install https://github.com/helm-unittest/helm-unittest --version v1.1.1
make helm-test
```
