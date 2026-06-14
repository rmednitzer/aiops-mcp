# ADR-0035: Release publish pipeline with signed provenance and SBOM attestation (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (closes the remaining BL-033 publish element)

## Context

ADR-0032 added the buildable, digest-pinned `Dockerfile` and a PR-CI `image`
workflow that build-validates it but never pushes (least privilege: pushing needs
registry write credentials, kept out of PR CI). Its revisit trigger named the next
step: "a release pipeline that builds and pushes the signed, attested image to the
registry (closes the remaining BL-033 published-digest element; consider provenance
and an image SBOM at that point)."

BL-033's residual is exactly that: there is no mechanism to publish the image, so
`deploy/helm/praxis/values.yaml` and `deploy/zarf.yaml` still carry an all-zero
placeholder digest. The placeholder is a deliberate fail-closed default (it fails at
pull time, it never silently runs an unpinned image), but the supply-chain story is
incomplete without a way to produce a real, signed, attested digest.

The constraints are the standing posture: digest never tag (ADR-0001); the human gate
between mechanism and a deployed change (the operator pins the digest, the pipeline
does not rewrite deploy manifests); least privilege (no write scope that the job does
not need); every action pinned by commit SHA and Renovate-maintained (ADR-0033). The
pipeline is untestable in PR CI by construction, because it fires only on a release
tag.

## Decision

1. A tag-triggered `release` workflow (`.github/workflows/release.yml`, `on: push:
   tags: ['v*']`) is the sole publisher. PR CI (`image.yml`) keeps build-validating
   and never pushes (ADR-0032 Decision 5 preserved). The job is guarded with `if:
   github.repository == 'rmednitzer/aiops-mcp'` so a fork cannot publish.

2. Least privilege. The job holds `contents: read`, `packages: write` (push the image
   and the attestation referrers to GHCR), `id-token: write` (the OIDC token GitHub
   uses to sign the attestations keylessly), and `attestations: write`. It has no
   `contents: write`: the pipeline does not commit the digest back into the deploy
   manifests. The operator pins it deliberately per `deploy/RELEASE-CHECKLIST.md`, so
   the human gate stays on the digest.

3. The pushed artifact is a plain single-arch (`linux/amd64`) image, with BuildKit's
   in-image provenance and SBOM disabled (`provenance: false`, `sbom: false`). This
   keeps the pushed digest a clean image-manifest digest, the one the operator pins,
   rather than an attestation-bearing index whose digest is muddier to reason about.

4. Provenance and the SBOM are GitHub-native, Sigstore-signed attestations
   (`actions/attest-build-provenance`, `actions/attest-sbom`), bound to the image
   digest, recorded in the GitHub attestations API and pushed to the registry as
   referrers (`push-to-registry: true`). An operator verifies both with a single
   command: `gh attestation verify oci://ghcr.io/rmednitzer/praxis@sha256:... -R
   rmednitzer/aiops-mcp`. The image SBOM is generated with syft (`anchore/sbom-action`)
   in CycloneDX JSON, matching the repo's existing CycloneDX choice (the environment
   SBOM in `sbom.yml`, BL-088).

5. No moving tags. `docker/metadata-action` runs with `flavor: latest=false`; the only
   tags pushed are the released semver (`{{version}}`, `{{major}}.{{minor}}`) and the
   source commit (`sha-<long>`), as human-readable registry pointers. The deploy
   manifests pin the digest, not any tag (ADR-0001).

6. Every action is pinned by commit SHA with a version comment, maintained by
   Renovate's `github-actions` manager (ADR-0033). Because the workflow is untestable
   in PR CI, the pins and inputs are reviewed rather than CI-proven; the SHAs were
   resolved to the head of each action's latest major and cross-checked.

7. The pipeline records the published digest and the verification command in the job
   summary. The all-zero placeholder in `values.yaml`/`zarf.yaml` stays the fail-closed
   default until the operator's first tagged release populates a real digest
   (RELEASE-CHECKLIST step 2). The mechanism (build, push, sign, attest, capture) is
   what this ADR delivers; the first real digest is an operator release action.

## Consequences

Positive: BL-033's publish and provenance/SBOM-attestation element is delivered. The
deployed image now has a complete, operator-verifiable supply-chain story (a signed
SLSA provenance attestation and a signed CycloneDX SBOM attestation bound to the
digest, verifiable with one `gh attestation verify`). The pipeline holds only the
scopes it needs, never commits to the repo, never publishes from a fork, and uses no
moving tags. The clean single-arch digest is straightforward to pin.

Negative: the workflow is untestable in PR CI (it fires only on a `v*` tag), so its
correctness rests on review and the pinned actions, not a green run. The first real
digest awaits the operator's first release; until then the placeholder remains (a
deliberate fail-closed default). The image is `linux/amd64` only; arm64 is a follow-up.
The base image (Docker Hub `python:slim`) and the registry (GHCR) are not yet
EU-sovereign (tracked under ADR-0032).

Neutral: the attestations sign the provenance and SBOM statements (Sigstore keyless),
not the image manifest itself; cosign image signing is a possible defense-in-depth
follow-up, not required for digest-bound attestation verification. The attestations are
registry referrers, so they do not change the image digest. The job authenticates to
GHCR with the built-in `GITHUB_TOKEN` (no long-lived registry secret).

## Alternatives considered and rejected

- Push from PR CI, or commit the digest back to the deploy manifests (`contents:
  write`). Rejected: registry-write or repo-write scope in CI is a privilege and a
  supply-chain risk, and committing the digest back removes the human gate on what the
  deployment runs. Publishing is a release operation; pinning the digest is the
  operator's deliberate act.
- BuildKit in-image attestations (`provenance: true`, `sbom: true`) as the primary
  mechanism. Rejected as primary: it turns the pushed artifact into an attestation-
  bearing index (a muddier digest to pin) and is not verifiable with `gh attestation
  verify`; the GitHub-native attestation path is the cleaner single-operator
  verification story. It remains available as a future defense-in-depth addition.
- A moving `latest` tag. Rejected: contrary to the ADR-0001 digest-pin posture; the
  deploy manifests must never depend on a mutable tag.
- Multi-arch (`linux/amd64` + `linux/arm64`). Deferred: a single arch keeps the pushed
  digest a plain image manifest and avoids QEMU emulation in the build; revisit when an
  arm64 fleet node appears (the digest then becomes an index and the pin guidance
  changes).
- A third-party publish/release action wrapping the whole flow. Rejected: composing the
  first-party `attest-*` actions with the standard `docker/*` actions, each SHA-pinned,
  is more reviewable and keeps the trust surface to vetted, individually pinned steps.

## Revisit triggers

- The operator cuts the first `v*` release: populate the real digest in
  `deploy/helm/praxis/values-prod.yaml` and `deploy/zarf.yaml` (RELEASE-CHECKLIST step
  2) and confirm `gh attestation verify` passes against the published digest.
- An arm64 fleet node appears: add `linux/arm64` to `platforms` (the digest becomes an
  index; revisit the pin guidance in the chart and zarf).
- An EU-sovereign base image and registry are adopted (the sovereignty boundary noted
  in ADR-0032).
- Stronger supply-chain hardening is wanted (cosign image signing, SLSA build-L3 with a
  hardened/reusable builder): add it alongside the attestations.
