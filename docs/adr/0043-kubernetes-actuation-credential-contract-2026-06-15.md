# ADR-0043: Kubernetes actuation credential contract: scoped static kubeconfig, or a bastion-host skill (2026-06-15)

## Status

Proposed

## Date

2026-06-15

## Authors

praxis maintainers (design decision before code; files BL-111)

## Context

praxis today manages Kubernetes only at the Talos control-plane layer: the
`talosctl` adapter (`src/praxis/actuation/talosctl.py`) carries cluster-lifecycle
verbs (`bootstrap`, `upgrade-k8s`, `kubeconfig`, with `reset`/`upgrade` at T3) for
`HostType.TALOS` hosts, and the classifier recognises `kubectl`
`apply|delete|scale|rollout|patch|edit|drain|cordon|uncordon` as T2
(`execution/patterns.py`). There is no first-class `kubectl` or `helm` actuation
adapter: a `kubectl` invocation today only reaches the fleet through the free-form
SSH adapter (floored at T2, ADR-0016), without native dry-run or structured-argument
hardening.

Whether `kubectl` and `helm` can become first-class audited actuators (rather than
remaining documented skills run on a bastion host) is decided by one thing: the
credential model. Two invariants bear directly on it. Invariant 9 requires
least-privilege, scoped, revocable credentials and forbids the `NOPASSWD: ALL`
equivalent. Invariant 8 (lethal-trifecta containment) treats all collected data as
untrusted and keeps a human gate between observation and actuation. A cluster
credential that is broad, ambient, or that runs an arbitrary helper per call cuts
against both.

The mechanism praxis already has:

- `CredentialBroker` (`actuation/credentials.py`) holds the authorization record
  only (role, exact hosts, max tier), independently revocable with `kill_all`; the
  secret material is injected out of band and never stored or logged (SEC-8).
- `scrubbed_env()` (`actuation/base.py`) forwards a small allowlist of credential
  references by name: `SSH_AUTH_SOCK`, `TALOSCONFIG`, and already `KUBECONFIG`
  (BL-080). Everything else in the server environment, including unrelated secrets,
  never reaches a wrapped tool or its plugins.
- `talosctl` is the precedent: a `TALOSCONFIG` provisioned out of band, with
  `--nodes`/`--endpoints` pinned from the trusted inventory (`config/inventory.yaml`),
  never from a free-form flag (BL-082).

Three Kubernetes-specific credential hazards make a naive adapter unsafe:

1. Context selection is ambient. `KUBECONFIG` is one process-wide variable whose
   current-context is mutable, so a call could silently target the wrong cluster.
2. Kubeconfigs are admin by default. A typical kubeconfig (including the one
   `talosctl kubeconfig` emits) grants cluster-admin, which is the standing-privilege
   posture invariant 9 forbids. Tiers gate the verb, not the blast radius of the
   credential.
3. Cloud and `exec` auth runs an arbitrary binary per call. EKS/GKE/AKS kubeconfigs
   carry a `user.exec` credential plugin (`aws eks get-token`, `gke-gcloud-auth-plugin`,
   `kubelogin`) that `kubectl`/`helm` execute on every invocation to mint a token. That
   plugin needs ambient cloud environment that `scrubbed_env()` deliberately strips
   (so it fails closed), and it is itself an unaudited arbitrary-subprocess actuation
   surface that praxis would be implicitly executing.

ArgoCD was considered alongside `kubectl`/`helm` and set aside: it is itself a GitOps
reconciler, overlapping the human-gated drift engine (ADR-0007 rejected continuous
auto-reconcile), and fits better as a future read-only desired-state drift source than
as an actuator.

## Decision

1. A first-class `kubectl`/`helm` actuation adapter is admissible only under the
   scoped-static-kubeconfig contract below. When that contract cannot be met (notably
   cloud or `exec`-plugin auth, or when only an admin kubeconfig exists), Kubernetes
   and Helm operations remain a bastion-host tool skill: a knowledge skill that
   documents the gated procedure on a bastion that already holds the cluster auth,
   where those actions are audited by the bastion rather than by praxis. This
   dividing line is the decision.

2. The scoped-static-kubeconfig contract:

   a. Credential. A static kubeconfig referenced out of band (`KUBECONFIG` is already
      allowlisted), holding a bearer token or client certificate for an RBAC-scoped
      principal, never cluster-admin. Scoping the kubeconfig is the operator's
      responsibility, the same posture as scoped SSH keys and `TALOSCONFIG` today. The
      `CredentialBroker` holds the cluster-host grant (role, host, max tier).

   b. Targeting from trusted inventory. The cluster is an inventory host vertex with a
      new `HostType.KUBERNETES`, carrying the kubeconfig path and the context name. The
      adapter pins `--kubeconfig <path> --context <ctx>` from the trusted inventory,
      validated, never from the caller and never from the ambient current-context.
      Kubeconfig paths are confined with `confine_to_root` (as ansible/tofu/runbook
      roots are), fail-closed when unset.

   c. Refuse `exec`-stanza kubeconfigs (fail closed). A kubeconfig whose selected
      context resolves to a `user.exec` credential plugin is rejected before any argv
      is built, for the two reasons in Context hazard 3. Cloud and `exec` auth therefore
      route to the bastion skill, not the adapter.

   d. Tiering and DRY_RUN. Verbs are allowlisted (the `talosctl` pattern). Reads are T0;
      `kubectl apply|scale|rollout|patch|cordon|drain` and `helm install|upgrade|rollback`
      are T2 (the `kubectl` mutators are already classified T2 in `patterns.py`);
      `helm uninstall`, `kubectl delete` of a namespace/PVC/CRD, and other
      hard-to-reverse verbs are T3 (typed token, one target at a time). Every real run
      is DRY_RUN then approve then execute, with native preview where the tool offers
      one (`kubectl --dry-run=server`/`kubectl diff`, `helm --dry-run`).

   e. host_type gate (SEC-5). The `kubectl`/`helm` adapters support only
      `HostType.KUBERNETES`; SSH, ansible, and talosctl refuse a KUBERNETES host and
      vice versa, as a HARD audited precondition, exactly as the Talos SSH refusal works.

   f. No free-form options (BL-082). Option-shaped tokens in the action string are
      refused; all options are set by the adapter from structured params; resource and
      namespace names are validated.

3. STPA traceability. Two new control actions, `act_kubectl` and `act_helm`, are added
   to `docs/stpa/05-ucas.md`, each with provide-type UCAs (act without DRY_RUN and
   approval; accept an `exec`-plugin or admin kubeconfig; wrong host_type), and each
   mapped to a covering security constraint in `07-security-constraints.md` (SEC-5
   host_type, SEC-6 DRY_RUN then approve, SEC-8 scoped credential). They are pre-staged
   and flagged `[planned]`, like the `act_redfish`/`act_cloud` rows (ADR-0022), until
   the adapter is implemented.

4. Default posture unchanged. This ADR builds nothing. With no KUBERNETES host in the
   inventory and no adapter registered, behaviour and the dependency set are unchanged.
   `kubectl` and `helm` are runtime tools discovered on `PATH` and wrapped (never
   vendored), consistent with the actuation-wraps-real-tools rule and the
   dependency-free core (ADR-0001/0014): no new Python dependency.

## Consequences

Positive: a clean, invariant-aligned dividing line between what praxis actuates
directly and what stays a bastion procedure. The scoped-kubeconfig path reuses
existing machinery (the `talosctl` adapter shape, the credential broker, `confine_to_root`,
the verb-allowlist and structured-argv hardening) with no new dependency. Cloud-auth
complexity is kept off the audited path by routing it to a skill. ArgoCD is kept out
of the actuation surface, avoiding a second reconciler beside the drift engine.

Negative: cloud-managed clusters (EKS/GKE/AKS) cannot be actuated through praxis
directly; their operators use the bastion skill and accept that those actions are
audited by the bastion, not by praxis. Multi-cluster requires one inventory host plus
one scoped kubeconfig and context per cluster; there is no ambient context switching.

Neutral: the eventual zero-standing-privilege answer is the roadmap Phase 4
`SecretSource` (JIT dynamic kubeconfig minting behind the broker,
`docs/roadmap/iam-access-and-secrets-expansion.md`); until that lands, a scoped static
kubeconfig is the contract. A short-TTL OIDC/`exec` credential plugin could be
allowlisted deliberately in future if the ambient-environment and arbitrary-subprocess
hazards are separately mitigated.

## Alternatives considered and rejected

- Widen `scrubbed_env()` to pass cloud credentials (`AWS_*`,
  `GOOGLE_APPLICATION_CREDENTIALS`, `kubelogin` variables) so `exec`-plugin kubeconfigs
  work. Rejected: it broadens the secret surface reaching every wrapped tool (against
  BL-080) and admits an arbitrary per-call subprocess onto the audited path.
- Accept an admin kubeconfig and rely on tiering alone. Rejected: standing
  cluster-admin is the `NOPASSWD: ALL` equivalent invariant 9 forbids; tiers gate the
  verb, not the credential's blast radius.
- Trust the kubeconfig current-context. Rejected: it is ambient and mutable, so a call
  could silently hit the wrong cluster; the context must come from trusted inventory.
- Run `kubectl`/`helm` only through the existing free-form SSH adapter with no dedicated
  adapter. Rejected as the default for the scoped case (it loses native dry-run, the
  structured-argument hardening, and the KUBERNETES host_type gate), but retained
  explicitly as the sanctioned path for the cloud/`exec`-auth case (the bastion skill).
- Build an ArgoCD actuator as well. Rejected: ArgoCD is itself a GitOps reconciler,
  overlapping the human-gated drift engine (ADR-0007); it fits a future read-only
  desired-state drift source, not the actuation surface.

## Revisit triggers

- The roadmap Phase 4 `SecretSource` lands, making short-TTL minted kubeconfigs the
  preferred path over a static scoped one.
- A vetted, bounded way to run an OIDC/`exec` credential plugin under an allowlisted
  environment, without widening the general `scrubbed_env()`, is designed.
- A requirement to actuate cloud-managed clusters directly (not via a bastion) is raised.
- ArgoCD or Flux desired-state ingestion is wanted as a drift source.
