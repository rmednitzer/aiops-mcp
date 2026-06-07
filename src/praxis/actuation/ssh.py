"""SSH/shell actuation adapter. Never targets a Talos host (SEC-5; invariant 5)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class SSHAdapter(ActuationAdapter):
    name: ClassVar[str] = "ssh"
    # Ubuntu and Windows (OpenSSH) only. Talos is API-only and immutable: there is
    # no shell to SSH into, so it is deliberately excluded (SEC-5).
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU, HostType.WINDOWS})
    base_tier: ClassVar[Tier] = Tier.T1
    native_dry_run: ClassVar[bool] = False  # no safe remote dry-run; preview instead

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        target = host.ssh_alias or host.name
        return ["ssh", target, action]
