"""talosctl actuation adapter. The ONLY actuation path for a Talos host (SEC-5).

Talos is API-only and immutable: there is no SSH. Endpoints are the control-plane
IPs talosctl connects to; nodes are the machines a request is about. Destructive
verbs (reset, upgrade) classify as T3 in the executor, so they require a typed
token and a single target.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class TalosctlAdapter(ActuationAdapter):
    name: ClassVar[str] = "talosctl"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.TALOS})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        argv = ["talosctl"]
        if host.nodes:
            argv += ["--nodes", ",".join(host.nodes)]
        if host.endpoints:
            argv += ["--endpoints", ",".join(host.endpoints)]
        argv += action.split()
        return argv
