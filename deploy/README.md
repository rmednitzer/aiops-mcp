# Deploy

Hardened deployment artifacts for praxis (BL-014).

## Contents

- `helm/praxis/` a secure-by-default Helm chart:
  - Pod Security Admission `restricted`: `runAsNonRoot`, non-root uid/gid,
    `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, all capabilities
    dropped, `seccompProfile: RuntimeDefault`.
  - A per-release ServiceAccount with `automountServiceAccountToken: false` (praxis
    needs no Kubernetes API access; invariant 9).
  - A default-deny `NetworkPolicy`: ingress only on the MCP port, egress only to
    DNS and explicitly listed fleet CIDRs (the in-cluster complement to the
    in-process SSRF filter, SEC-7). (v0 gap: the ingress rule has no `from:`
    selector, so any pod can reach the MCP port, and the DNS egress is not
    namespace-scoped; BL-051, BL-087.)
  - A digest-pinned image (no tags; ADR-0001 supply-chain posture). Set
    `image.digest` before installing. (v0 gap: the default `image.digest` is an
    all-zero placeholder that only fails at pull time; BL-033.)
  - An optional hardened `runtimeClassName` for the code-executing plane.
- `systemd/praxis.service` plus `praxis.service.d/hardening.conf` for a host
  install. Verify with `systemd-analyze security praxis.service`.
- `zarf.yaml` for an airgap package (chart plus the pinned image).

## Status

The container/Helm/systemd run target the streamable-HTTP transport, which is
opt-in and fails closed without a token and the non-loopback acknowledgement
(ADR-0006). HTTP serving itself is staged behind the enforced transport guard (see
`LIMITATIONS.md`); the default, fully working deployment is stdio on a workstation
(`python -m praxis`). These manifests encode the production hardening posture so it
is reviewable now and ready when HTTP serving lands.

## Known hardening gaps (tracked)

The manifests encode the intended posture; the deep review (ADR-0015) found these
gaps to that bar, each tracked in `docs/backlog.md`:

- `storeDsn` (the PostgreSQL DSN, which carries the password) renders as a plaintext
  Deployment env value, so it lands in etcd and `helm history`; move it to a
  `secretKeyRef` (the http token already uses one). BL-086.
- The `NetworkPolicy` ingress has no `from:` selector and the DNS egress is not
  namespace-scoped. BL-051, BL-087.
- The default image digest is an all-zero placeholder. BL-033.
- The systemd hardening drop-in is missing `PrivateUsers`, `ProcSubset=pid`,
  `RemoveIPC`, and `IPAddressDeny`/`SocketBindDeny`, and `runtimeClassName` defaults
  to empty (no sandbox). BL-087.

## Quickstart (stdio, no cluster)

```
uv venv --python 3.12 .venv && uv pip install --python .venv -e .
PRAXIS_MODE=guarded .venv/bin/python -m praxis   # speaks MCP JSON-RPC over stdio
```
