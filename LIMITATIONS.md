# Limitations and scope boundaries

This file states what `praxis` is not, and the known gaps at the current phase.

## Phase

Bootstrapping. The repository is scaffolded governance-first; the implementation
is built by following `docs/first-session.md`. Treat every component as "planned"
until its tests exist and pass.

## Scope boundaries

- Not a model-training or model-serving platform. It operates infrastructure; it
  does not host inference workloads.
- Not a general SIEM. It tracks host/fleet state and drift; it integrates with,
  but does not replace, log pipelines or detection engines.
- Not a replacement for IaC or configuration management. It WRAPS OpenTofu,
  Ansible, runbooks, and talosctl; the desired-state authorities remain those
  tools.

## Known gaps (to be closed via the backlog)

- Capability isolation for actuation subprocesses (container/seccomp) is an
  out-of-tree extension point at v0.
- Multi-operator/multi-tenant authorization is not a v0 goal; the default posture
  is single-operator with scoped credentials.
- Windows actuation depth (beyond observation) is staged after the Linux and
  Talos paths.
