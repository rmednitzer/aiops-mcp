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
    filter, SEC-7; BL-087).
  - A digest-pinned image (no tags; ADR-0001 supply-chain posture). Set
    `image.digest` before installing. (v0 gap: the default `image.digest` is an
    all-zero placeholder that only fails at pull time; BL-033.)
  - An optional hardened `runtimeClassName` for the code-executing plane.
  - `values-prod.yaml`: a production overlay (BL-036) that makes the hardened posture
    explicit and marks the operator-supplied values (the image digest, the NetworkPolicy
    peers and egress) a real deployment must set. It never weakens a default.
- `systemd/praxis.service` plus `praxis.service.d/hardening.conf` for a host
  install. Verify with `systemd-analyze security praxis.service`.
- `zarf.yaml` for an airgap package (chart plus the pinned image).
- `RELEASE-CHECKLIST.md`: the ordered version-bump checklist (gates, image digest,
  chart `version`/`appVersion`, SBOM, tag) so a release never ships an unpinned image
  or a stale SBOM (BL-036).

## Status

The container/Helm/systemd run target the streamable-HTTP transport, which is
opt-in and fails closed without a token and the non-loopback acknowledgement
(ADR-0006). HTTP serving itself is staged behind the enforced transport guard (see
`LIMITATIONS.md`); the default, fully working deployment is stdio on a workstation
(`python -m praxis`). These manifests encode the production hardening posture so it
is reviewable now and ready when HTTP serving lands.

## Known hardening gaps (tracked)

The manifests encode the intended posture; the deep review (ADR-0015) found these
gaps to that bar, each tracked in `docs/backlog.md`. The ADR-0018 wave closed the
`storeDsn` plaintext rendering (now a `secretKeyRef`, with an inline DSN refused at
render time, BL-086) and the unselective ingress (now `networkPolicy.ingressFrom`,
deny-all by default, BL-051). The ADR-0020 wave scoped the DNS egress to
`kube-system`, made `egressCIDRs` `{cidr, except}` objects that always excise
169.254.0.0/16 (cloud metadata and link-local), and added the systemd
`PrivateUsers`/`ProcSubset=pid`/`RemoveIPC` lockdown plus de-duplicated the base
unit against the drop-in (BL-087). Still open:

- The default image digest is an all-zero placeholder. BL-033. No Dockerfile in
  the repo builds the referenced image. BL-092.
- `IPAddressDeny`/`SocketBindDeny` and a sandbox `runtimeClassName` are documented
  in the drop-in but left for the operator to scope to their fleet (a deny-all
  default would brick SSH actuation). BL-087 note.

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
