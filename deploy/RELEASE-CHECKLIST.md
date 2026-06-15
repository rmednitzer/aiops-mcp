# Release / version-bump checklist

A short, ordered checklist for cutting a praxis release and bumping the Helm chart
(BL-036). The goal is that a version bump never ships an unpinned image, a stale SBOM,
or a chart whose `appVersion` lags the code. Dates are ISO 8601; keep the `## What
this is` posture in `CLAUDE.md` (never weaken a default to make a step pass).

## 1. Code and gates

- [ ] `make check` green (ruff + mypy strict + pytest).
- [ ] `make schema` regenerated and committed if any tool arg model or skill manifest
      changed (the schema-drift guard is in `ci-success`).
- [ ] `make eval` and `make validate-compliance` green.
- [ ] `make helm-test` green (the chart assertions, BL-032).
- [ ] `CHANGELOG.md` `[Unreleased]` section reflects every user-visible change, each
      citing its `BL-NNN` and ADR.

## 2. Image (supply chain, ADR-0001, ADR-0035)

Publishing is automated and triggered by the release tag (step 4): pushing a `v*`
tag runs the `release` workflow (`.github/workflows/release.yml`), which builds and
pushes the image to GHCR with a signed provenance and a CycloneDX SBOM attestation.
It is the only workflow that pushes; never publish by hand. The digest-capture and
pin sub-steps below are therefore done after the tag fires (step 4).

- [ ] Confirm the CI `image` workflow build-validated the `Dockerfile` (BL-092,
      ADR-0032) on the release commit (it runs on every PR and on `main`).
- [ ] After the tag fires, read the immutable `sha256:` digest from the `release`
      workflow's job summary (never a tag), and verify the attestations:
      `gh attestation verify oci://ghcr.io/rmednitzer/praxis@sha256:... -R rmednitzer/aiops-mcp`.
- [ ] Set `image.digest` in `deploy/helm/praxis/values-prod.yaml` (or pass
      `--set image.digest=...` at install) to that digest, and set the same digest in
      `deploy/zarf.yaml` (BL-033 supply-chain parity). This is the human gate on the
      digest: the pipeline records it, the operator pins it (no `contents: write`).
- [ ] The `release` workflow already attached a CycloneDX image-SBOM attestation; the
      `sbom` workflow (`.github/workflows/sbom.yml`) separately covers the Python
      environment graph.

## 3. Chart version

- [ ] Bump `deploy/helm/praxis/Chart.yaml` `version` (chart) on any chart change.
- [ ] Bump `Chart.yaml` `appVersion` to the released application version.
- [ ] `helm lint deploy/helm/praxis` passes.
- [ ] `helm template deploy/helm/praxis -f deploy/helm/praxis/values-prod.yaml --set image.digest=sha256:...` renders cleanly.

## 4. Tag and record

- [ ] Move the `CHANGELOG.md` `[Unreleased]` entries under the new version heading
      with the release date.
- [ ] Tag the release commit; confirm CI (the `ci-success` aggregate plus codeql,
      dependency-review, sbom, fuzz) is green on it.
- [ ] Pushing the `v*` tag triggers the `release` workflow (ADR-0035): it publishes the
      image and its signed provenance and SBOM attestations to GHCR. Return to step 2 to
      capture and pin the published digest, then commit the pinned manifests.

## 5. Deploy verification (HTTP transport, BL-012/ADR-0041)

- [ ] In a staging namespace, `helm install` with `values-prod.yaml` and a real digest;
      confirm the pod reaches Ready (the probes, BL-060) and the NetworkPolicy admits
      only the named MCP client (BL-051/BL-087).
- [ ] Confirm the audit log and evidence files are on OS append-only storage
      (`chattr +a` / WORM) per `SECURITY.md`, the required control while the default
      keyless `LocalStamper` is in use; the opt-in RFC 3161 TSA stamper (BL-095,
      ADR-0030) is the non-forgeable alternative.
