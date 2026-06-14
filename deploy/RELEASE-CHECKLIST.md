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

## 2. Image (supply chain, ADR-0001)

- [ ] Build the image from the repo `Dockerfile` (BL-092, ADR-0032) on the
      digest-pinned base; the CI `image` workflow build-validates it on every PR.
- [ ] Publish it and capture the immutable `sha256:` digest (never a tag).
- [ ] Set `image.digest` in `deploy/helm/praxis/values-prod.yaml` (or pass
      `--set image.digest=...` at install); confirm `deploy/zarf.yaml` references the
      same digest (BL-033 supply-chain parity).
- [ ] Regenerate the SBOM (`.github/workflows/sbom.yml`) for the published graph.

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

## 5. Deploy verification (when HTTP serving lands, BL-012)

- [ ] In a staging namespace, `helm install` with `values-prod.yaml` and a real digest;
      confirm the pod reaches Ready (the probes, BL-060) and the NetworkPolicy admits
      only the named MCP client (BL-051/BL-087).
- [ ] Confirm the audit log and evidence files are on OS append-only storage
      (`chattr +a` / WORM) per `SECURITY.md`, the required control while the default
      keyless `LocalStamper` is in use; the opt-in RFC 3161 TSA stamper (BL-095,
      ADR-0030) is the non-forgeable alternative.
