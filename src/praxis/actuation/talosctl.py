"""talosctl actuation adapter. The ONLY actuation path for a Talos host (SEC-5).

Talos is API-only and immutable: there is no SSH. Endpoints are the control-plane
IPs talosctl connects to; nodes are the machines a request is about. Destructive
verbs (reset, upgrade) classify as T3 in the executor, so they require a typed
token and a single target.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.contract import Approval
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionRequest
from praxis.model.facts import HostType

# An allowlist of talosctl subcommands, so a free-form ``action`` string can no
# longer smuggle an arbitrary or typo'd verb into the argv (BL-048). New verbs are
# added here deliberately; an unknown verb is refused before the argv is built.
_TALOSCTL_VERBS: frozenset[str] = frozenset(
    {
        # read-only / diagnostic
        "version",
        "health",
        "get",
        "list",
        "read",
        "dmesg",
        "logs",
        "services",
        "containers",
        "memory",
        "processes",
        "stats",
        "disks",
        "mounts",
        "time",
        "members",
        "kubeconfig",
        # stateful
        "apply-config",
        "patch",
        "bootstrap",
        # destructive (classify T3 in the executor)
        "reset",
        "upgrade",
        "upgrade-k8s",
        "reboot",
        "shutdown",
        "etcd",
    }
)


class TalosctlAdapter(ActuationAdapter):
    name: ClassVar[str] = "talosctl"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.TALOS})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False

    def build_request(
        self,
        host: HostInfo,
        action: str,
        params: Mapping[str, object] | None = None,
        *,
        dry_run: bool = True,
        approval: Approval | None = None,
    ) -> ExecutionRequest:
        request = super().build_request(host, action, params, dry_run=dry_run, approval=approval)
        if host.nodes:
            # The T3 single-target gate keys off ``request.target``; for talosctl the
            # real targets are the nodes, not host.name. Reflect them so a multi-node
            # destructive call (reset/upgrade across the control plane at once) is
            # refused by the executor's one-target-at-a-time rule, not just a
            # multi-name one (BL-047). A comma in the target trips _is_multi_target.
            return replace(request, target=",".join(host.nodes))
        return request

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        parts = action.split()
        if not parts:
            raise ValueError("talosctl requires a verb")
        verb = parts[0]
        if verb not in _TALOSCTL_VERBS:
            raise ValueError(
                f"talosctl verb not allowed: {verb!r} (allowed: {sorted(_TALOSCTL_VERBS)})"
            )
        argv = ["talosctl"]
        if host.nodes:
            argv += ["--nodes", ",".join(host.nodes)]
        if host.endpoints:
            argv += ["--endpoints", ",".join(host.endpoints)]
        argv += parts
        return argv
