"""Ansible actuation adapter (Ubuntu). DRY_RUN maps to a native ``--check`` run."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class AnsibleAdapter(ActuationAdapter):
    name: ClassVar[str] = "ansible"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = True  # --check is a safe, real preview

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        # action is the playbook path; --limit scopes to a single host.
        argv = ["ansible-playbook", action, "--limit", host.name]
        if dry_run:
            argv.append("--check")
        return argv
