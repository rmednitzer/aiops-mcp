"""CIS-Talos desired-state baseline as drift data (BL-099, ADR-0024).

This turns the CIS Kubernetes Benchmark, with the Talos-defaults mapping, into
``KNOWN_GOOD`` facts the existing drift engine can diff against collected state. It
adds no engine change and no actuation: drift stays read-only (T0, SEC-6) and all
collected/observed values are untrusted data, only compared, never interpreted
(SEC-4). The schema is fixed by ADR-0024:

- subject is the real asset: ``host:<name>`` for node and control-plane component
  controls, ``cluster:<name>`` for genuine singletons.
- predicate is ``cis:<benchmark>:<control_id>``; ``<benchmark>`` versions the source
  so a benchmark revision is a new namespace, not a silent redefinition.
- ``value`` carries only the normalized, collector-reproducible setting
  (``{"value": <normalized>}``); all documentation lives in ``reason`` (a JSON
  string the diff ignores), so metadata never manufactures a spurious ``CHANGED``.
- severity comes through the engine's ``severity_for`` hook: any ``cis:`` control is
  security-relevant and ranks ``CRITICAL``.
- false positives are two explicit, documented, reviewable sets: ``TALOS_SATISFIED``
  (Talos enforces it structurally, nothing can drift) and ``CIS_SUPPRESSED`` (an
  operator waiver). Both are excluded from the baseline rather than silently masked.

The baseline below is an initial, vetted set across the kubelet, API-server,
controller-manager, scheduler, and cluster control families, structured so adding a
control or a new ``<benchmark>`` namespace is additive. Each control cites its CIS
reference in ``reason``.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from praxis.clock import utc_now_iso
from praxis.drift.engine import default_severity, diff
from praxis.drift.findings import DriftFinding, DriftKind, DriftSeverity
from praxis.model.facts import KNOWN_GOOD, Fact
from praxis.store.base import StoreProtocol

CIS_BENCHMARK_DEFAULT = "talos"

Scope = Literal["node", "controlplane", "cluster"]


def normalize_value(raw: object) -> str:
    """Normalize a setting to the one comparable form used on both sides (ADR-0024).

    Booleans lowercase to ``"true"``/``"false"``; scalars cast to a trimmed string;
    a list (or a comma-joined string) trims, lowercases its boolean tokens, sorts,
    and rejoins, so order does not matter. Applied identically by the baseline and
    the collector, a compliant node compares equal and only a real difference yields
    ``CHANGED``.
    """
    if isinstance(raw, bool):
        return "true" if raw else "false"
    if isinstance(raw, (list, tuple)):
        items = [str(x) for x in raw]
    else:
        text = str(raw).strip()
        items = [part.strip() for part in text.split(",")] if "," in text else [text]
    tokens = [tok.lower() if tok.lower() in ("true", "false") else tok for tok in items]
    if len(tokens) == 1:
        return tokens[0]
    return ",".join(sorted(tokens))


@dataclass(frozen=True)
class CisControl:
    """One CIS/Talos control as a comparable desired value plus documentation."""

    control_id: str
    scope: Scope
    desired: object
    title: str
    level: int
    scored: bool
    cis_ref: str
    rationale: str
    remediation: str
    benchmark: str = CIS_BENCHMARK_DEFAULT

    @property
    def key(self) -> str:
        """The ``<benchmark>:<control_id>`` key used by the suppression sets."""
        return f"{self.benchmark}:{self.control_id}"

    @property
    def predicate(self) -> str:
        return f"cis:{self.benchmark}:{self.control_id}"

    def desired_value(self) -> dict[str, object]:
        return {"value": normalize_value(self.desired)}

    def reason_json(self) -> str:
        return json.dumps(
            {
                "id": self.control_id,
                "benchmark": self.benchmark,
                "title": self.title,
                "level": self.level,
                "scored": self.scored,
                "cis_ref": self.cis_ref,
                "rationale": self.rationale,
                "remediation": self.remediation,
            },
            sort_keys=True,
            ensure_ascii=False,
        )

    def to_known_good(self, subject: str, actor: str) -> Fact:
        return Fact(
            subject=subject,
            predicate=self.predicate,
            fact_type=KNOWN_GOOD,
            value=self.desired_value(),
            t_valid=utc_now_iso(),
            actor=actor,
            reason=self.reason_json(),
        )


# The vetted baseline. Talos runs the control-plane components as static pods on each
# control-plane node, so their flags are control-plane-node scoped (ADR-0024 dec. 2).
CIS_BASELINE: tuple[CisControl, ...] = (
    # Kubelet (CIS Kubernetes Benchmark section 4.2), node-scoped.
    CisControl(
        "kubelet-anonymous-auth",
        "node",
        False,
        "Kubelet anonymous auth disabled",
        1,
        True,
        "k8s 4.2.1",
        "Anonymous requests to the kubelet must be rejected.",
        "Set the kubelet --anonymous-auth flag (or KubeletConfiguration) to false.",
    ),
    CisControl(
        "kubelet-authorization-mode",
        "node",
        "Webhook",
        "Kubelet authorization mode is not AlwaysAllow",
        1,
        True,
        "k8s 4.2.2",
        "The kubelet must authorize requests via Webhook, not AlwaysAllow.",
        "Set the kubelet --authorization-mode to Webhook.",
    ),
    CisControl(
        "kubelet-read-only-port",
        "node",
        0,
        "Kubelet read-only port disabled",
        1,
        True,
        "k8s 4.2.4",
        "The unauthenticated read-only port exposes node and pod data; disable it.",
        "Set the kubelet --read-only-port to 0.",
    ),
    CisControl(
        "kubelet-protect-kernel-defaults",
        "node",
        True,
        "Kubelet protect-kernel-defaults enabled",
        1,
        True,
        "k8s 4.2.6",
        "The kubelet must not override safe kernel defaults.",
        "Set the kubelet --protect-kernel-defaults to true.",
    ),
    CisControl(
        "kubelet-make-iptables-util-chains",
        "node",
        True,
        "Kubelet manages iptables util chains",
        1,
        True,
        "k8s 4.2.7",
        "The kubelet must maintain the iptables utility chains it relies on.",
        "Set the kubelet --make-iptables-util-chains to true.",
    ),
    CisControl(
        "kubelet-rotate-certificates",
        "node",
        True,
        "Kubelet client certificate rotation enabled",
        1,
        True,
        "k8s 4.2.11",
        "Kubelet client certificates must rotate so a leaked cert expires.",
        "Set the kubelet --rotate-certificates to true.",
    ),
    CisControl(
        "kubelet-rotate-server-certificates",
        "node",
        True,
        "Kubelet server certificate rotation enabled",
        1,
        True,
        "k8s 4.2.12",
        "Kubelet serving certificates must rotate via the CSR API.",
        "Enable RotateKubeletServerCertificate on the kubelet.",
    ),
    # A checkable control the operator waives: listed here but excluded from the active
    # set via CIS_SUPPRESSED below, so suppression is a named waiver of a real control.
    CisControl(
        "kubelet-event-qps",
        "node",
        0,
        "Kubelet event QPS cap",
        2,
        False,
        "k8s 4.2.9",
        "An operational rate-limit knob for kubelet event creation, not a security control.",
        "Set the kubelet --event-qps to the value appropriate for the fleet's load.",
    ),
    # kube-apiserver (CIS section 1.2), control-plane-node scoped.
    CisControl(
        "apiserver-anonymous-auth",
        "controlplane",
        False,
        "API server anonymous auth disabled",
        1,
        True,
        "k8s 1.2.1",
        "Anonymous requests to the API server must be rejected.",
        "Set kube-apiserver --anonymous-auth to false.",
    ),
    CisControl(
        "apiserver-profiling",
        "controlplane",
        False,
        "API server profiling disabled",
        1,
        True,
        "k8s 1.2.21",
        "The profiling endpoint exposes detailed system information; disable it.",
        "Set kube-apiserver --profiling to false.",
    ),
    CisControl(
        "apiserver-authorization-mode",
        "controlplane",
        ["Node", "RBAC"],
        "API server authorization mode is Node,RBAC",
        1,
        True,
        "k8s 1.2.7",
        "Authorization must use Node and RBAC, never AlwaysAllow.",
        "Set kube-apiserver --authorization-mode to Node,RBAC.",
    ),
    CisControl(
        "apiserver-service-account-lookup",
        "controlplane",
        True,
        "API server validates service account tokens against etcd",
        1,
        True,
        "k8s 1.2.13",
        "A deleted service account's token must stop working immediately.",
        "Set kube-apiserver --service-account-lookup to true.",
    ),
    # kube-controller-manager (CIS section 1.3), control-plane-node scoped.
    CisControl(
        "controller-manager-profiling",
        "controlplane",
        False,
        "Controller-manager profiling disabled",
        1,
        True,
        "k8s 1.3.2",
        "The profiling endpoint exposes detailed system information; disable it.",
        "Set kube-controller-manager --profiling to false.",
    ),
    CisControl(
        "controller-manager-use-service-account-credentials",
        "controlplane",
        True,
        "Controller-manager uses individual service account credentials",
        1,
        True,
        "k8s 1.3.3",
        "Each controller must run with its own least-privilege credential.",
        "Set kube-controller-manager --use-service-account-credentials to true.",
    ),
    CisControl(
        "controller-manager-bind-address",
        "controlplane",
        "127.0.0.1",
        "Controller-manager bound to loopback",
        1,
        True,
        "k8s 1.3.7",
        "The controller-manager must not expose its port beyond the node.",
        "Set kube-controller-manager --bind-address to 127.0.0.1.",
    ),
    # kube-scheduler (CIS section 1.4), control-plane-node scoped.
    CisControl(
        "scheduler-profiling",
        "controlplane",
        False,
        "Scheduler profiling disabled",
        1,
        True,
        "k8s 1.4.1",
        "The profiling endpoint exposes detailed system information; disable it.",
        "Set kube-scheduler --profiling to false.",
    ),
    CisControl(
        "scheduler-bind-address",
        "controlplane",
        "127.0.0.1",
        "Scheduler bound to loopback",
        1,
        True,
        "k8s 1.4.2",
        "The scheduler must not expose its port beyond the node.",
        "Set kube-scheduler --bind-address to 127.0.0.1.",
    ),
    # Cluster singleton (CIS section 5.2): the cluster-wide Pod Security default.
    CisControl(
        "cluster-default-pod-security",
        "cluster",
        "restricted",
        "Cluster default Pod Security Standard is restricted",
        1,
        False,
        "k8s 5.2.1",
        "Namespaces without an explicit policy must default to the restricted PSS.",
        "Configure the PodSecurity admission default to enforce the restricted standard.",
    ),
)

# Controls Talos enforces structurally and immutably: there is nothing a node could
# drift to, so they are documented as platform-guaranteed and excluded from the diff
# rather than checked (ADR-0024 dec. 6). Keyed ``<benchmark>:<control_id>``.
TALOS_SATISFIED: dict[str, str] = {
    "talos:node-no-ssh": (
        "Talos exposes no shell or SSH; node-level interactive access does not exist "
        "(host_type=talos, SEC-5), so the host-access hardening controls cannot drift."
    ),
    "talos:kubelet-config-file-perms": (
        "The kubelet config is delivered by immutable Talos machine config, not a "
        "writable on-disk file a node could re-permission (CIS 4.1 file-perm controls)."
    ),
    "talos:apiserver-manifest-file-perms": (
        "Control-plane static-pod manifests and their ownership/permissions are managed "
        "by Talos as immutable machine config (CIS 1.1 manifest-file controls)."
    ),
    "talos:etcd-data-dir-perms": (
        "The etcd data directory ownership and permissions are managed by Talos and not "
        "mutable from a node (CIS 1.1.11/1.1.12)."
    ),
}

# Operator waivers: each is a real, re-reviewable decision with a one-line rationale,
# never a blanket ignore (ADR-0024 dec. 6). A waived control is a baseline control
# (above) whose key appears here; it is dropped from the active set so neither the CIS
# diff nor the generic scan alerts on it. Operators extend this set per environment.
CIS_SUPPRESSED: dict[str, str] = {
    "talos:kubelet-event-qps": (
        "Event QPS is an operational throughput knob (CIS Level 2, not scored), tuned "
        "per fleet load rather than enforced as a security control (operator-reviewable)."
    ),
}

_EXCLUDED: frozenset[str] = frozenset(TALOS_SATISFIED) | frozenset(CIS_SUPPRESSED)


def active_controls() -> tuple[CisControl, ...]:
    """The baseline controls actually diffed (TALOS_SATISFIED/CIS_SUPPRESSED removed)."""
    return tuple(c for c in CIS_BASELINE if c.key not in _EXCLUDED)


def active_control_keys() -> frozenset[str]:
    """The ``<benchmark>:<control_id>`` keys of the controls actually diffed."""
    return frozenset(c.key for c in active_controls())


def cis_severity(predicate: str, kind: DriftKind) -> DriftSeverity:
    """Rank any ``cis:`` control's drift CRITICAL; delegate everything else.

    CIS drift is security-relevant in every direction (a weakened flag, a missing
    control, an unexpected one), consistent with the engine's ``_SECURITY_PREDICATES``
    posture (ADR-0024 dec. 5). Non-CIS predicates fall back to ``default_severity``,
    so this is safe to pass to the generic scan over a mixed baseline.
    """
    if predicate.startswith("cis:"):
        return DriftSeverity.CRITICAL
    return default_severity(predicate, kind)


def _subjects_for(
    scope: Scope,
    nodes: Sequence[str],
    control_plane_nodes: Sequence[str],
    clusters: Sequence[str],
) -> list[str]:
    if scope == "node":
        return [f"host:{n}" for n in nodes]
    if scope == "controlplane":
        return [f"host:{n}" for n in control_plane_nodes]
    return [f"cluster:{c}" for c in clusters]


def cis_baseline_facts(
    *,
    nodes: Sequence[str] = (),
    control_plane_nodes: Sequence[str] = (),
    clusters: Sequence[str] = (),
    actor: str = "cis-baseline",
) -> list[Fact]:
    """Materialize the active CIS baseline as ``KNOWN_GOOD`` facts for the given assets.

    Node controls attach to every node; control-plane component controls to every
    control-plane node; cluster singletons to every cluster. Suppressed and
    Talos-satisfied controls are excluded.
    """
    facts: list[Fact] = []
    for control in active_controls():
        for subject in _subjects_for(control.scope, nodes, control_plane_nodes, clusters):
            facts.append(control.to_known_good(subject, actor))
    return facts


def cis_drift(
    observed: Iterable[Fact],
    *,
    nodes: Sequence[str] = (),
    control_plane_nodes: Sequence[str] = (),
    clusters: Sequence[str] = (),
) -> list[DriftFinding]:
    """Diff observed CIS facts against the materialized baseline (CIS-aware severity).

    ``flag_unexpected`` is off: a node legitimately carries many settings beyond the
    CIS controls, so only the baselined controls are checked. A baselined control with
    no observed fact surfaces as ``MISSING`` (an unevaluable hardening control is shown,
    not silently passed).
    """
    desired = cis_baseline_facts(
        nodes=nodes, control_plane_nodes=control_plane_nodes, clusters=clusters
    )
    return diff(observed, desired, flag_unexpected=False, severity_for=cis_severity)


def seed_cis_baseline(
    store: StoreProtocol,
    *,
    nodes: Sequence[str] = (),
    control_plane_nodes: Sequence[str] = (),
    clusters: Sequence[str] = (),
    actor: str = "cis-baseline",
) -> int:
    """Write the CIS baseline into the store as known-good facts; return the count.

    A library helper, not an MCP tool: blessing a desired baseline is an operator
    action like the other known-good seeds (BL-016), and adds no actuation surface.
    """
    facts = cis_baseline_facts(
        nodes=nodes, control_plane_nodes=control_plane_nodes, clusters=clusters, actor=actor
    )
    for fact in facts:
        store.put_fact(fact)
    return len(facts)
