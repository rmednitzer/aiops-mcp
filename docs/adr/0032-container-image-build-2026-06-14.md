# ADR-0032: Container image build (multi-stage, non-root, digest-pinned) (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (implements BL-092; advances BL-033)

## Context

`deploy/helm/praxis/values.yaml` and `deploy/zarf.yaml` reference a digest-pinned
`ghcr.io/rmednitzer/praxis` image (ADR-0001 supply-chain posture), but no `Dockerfile`
in the repo builds it (BL-092), and the default digest is an all-zero placeholder
(BL-033). The deployed container could not be built or inspected from source, at odds
with the digest-pin posture and the self-contained, reviewable-by-one-operator goal.

The runtime is small: the execution core is dependency-free and the only default
runtime dependency is `pydantic` (ADR-0001, ADR-0014); the `tsa` and `postgres`
extras are opt-in. The default, fully working transport is stdio (`python -m praxis`);
HTTP serving is staged, not implemented (BL-012, BL-093).

## Decision

1. Add a multi-stage `Dockerfile` at the repo root. A builder stage installs the
   project (default runtime deps only, no extras) into a venv; a clean runtime stage
   copies the venv and runs `python -m praxis`. The build artifact is minimal and
   carries none of the build toolchain.

2. Pin the base by digest. `python:3.12-slim-bookworm` is pinned by `sha256:` digest
   with the tag in a comment so Renovate can maintain it (the same bounded-then-pinned
   discipline used for CI actions and the dev lock, BL-088). Distroless is rejected
   for the runtime stage because `gcr.io/distroless/python3-debian12` ships Python
   3.11, below the project's `requires-python >=3.12` floor.

3. Non-root by construction. The image creates a fixed, high, system uid/gid
   (`10001`) with no login shell and runs as it (`USER 10001`), so the image is
   non-root independent of the orchestrator. This complements, not replaces, the Helm
   chart's PSA-restricted `securityContext` (BL-014).

4. Governance-as-code labels (BL-033). The runtime stage carries OCI labels
   (`org.opencontainers.image.*` including `base.name`/`base.digest`) and an
   `io.praxis.governance` label pointing at the governing ADRs and the backlog, so
   the deployed bytes carry their own provenance and traceability.

5. Validate in CI, never push from CI. A new `image` workflow builds the image and
   runs a non-root import smoke test on every PR and on `main`, so the Dockerfile
   cannot rot and the deploy manifests have a CI-validated, buildable source. The
   published image and its immutable digest are produced at release time
   (`deploy/RELEASE-CHECKLIST.md`), not on every PR; pushing needs registry
   credentials and is a release operation, kept out of PR CI (least privilege).

## Consequences

Positive: the deployed image is buildable and inspectable from source; it is minimal
and non-root by construction; the base is digest-pinned and Renovate-maintained; the
Dockerfile is CI-validated so it cannot silently break; BL-092 is closed.

Negative: BL-033 is advanced but not fully closed. The published digest in
`values.yaml`/`zarf.yaml` stays an all-zero placeholder until an actual release builds
and pushes the image to a registry, which requires registry credentials and a release
pipeline (out of scope here, tracked under BL-033). The base is a Docker Hub official
image; a fully EU-sovereign base and registry is a documented follow-up, not delivered
here.

Neutral: the image's default transport is stdio (it refuses an unsafe HTTP bind, fails
closed); it becomes directly runnable as a server when HTTP serving lands (BL-012).
The `tsa`/`postgres` extras are not in the default image; an operator who needs them
builds a derived image or extends the build.

## Alternatives considered and rejected

- Distroless runtime stage. Rejected: the distroless python3 image is Python 3.11,
  below the 3.12 floor; carrying a custom-built Python into distroless adds more
  supply-chain surface than the slim base it would replace.
- Pin the base by tag only. Rejected: a tag is mutable, contrary to the ADR-0001
  digest-pin posture; the digest pin with a tag comment keeps Renovate able to update
  it.
- Build and push from PR CI to produce the digest. Rejected: pushing needs registry
  write credentials in PR CI (a privilege and a supply-chain risk on untrusted PRs);
  publishing is a release operation, kept separate.
- Only document the external build (the BL-092 "or" path). Rejected: a real, minimal,
  CI-validated Dockerfile is more reviewable and closes the gap rather than describing
  around it.

## Revisit triggers

- A release pipeline that builds and pushes the signed, attested image to the registry
  lands (closes the remaining BL-033 published-digest element; consider provenance and
  an image SBOM at that point).
- An EU-sovereign base image and registry are adopted (sovereignty boundary).
- HTTP serving lands (BL-012): revisit the entrypoint, a readiness probe, and the
  exposed port.
