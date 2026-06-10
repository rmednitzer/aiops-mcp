"""Ansible actuation adapter (Ubuntu). DRY_RUN maps to a native ``--check`` run.

Input hardening (BL-081, ADR-0016): the ``--limit`` host comes from inventory but
is validated against the shared safe-target pattern anyway (defense in depth
against option injection), and the playbook path is confined to the configured
playbook root (fail closed when unset), so a hostile ``action`` cannot point
``ansible-playbook`` at an arbitrary filesystem path.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import SAFE_TARGET, ActuationAdapter, HostInfo, confine_to_root
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class AnsibleAdapter(ActuationAdapter):
    name: ClassVar[str] = "ansible"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = True  # --check is a safe, real preview

    def __init__(self, playbook_root: str | None = None) -> None:
        # The only directory playbooks may run from (PRAXIS_PLAYBOOK_ROOT).
        # None refuses every playbook: fail closed (BL-081).
        self.playbook_root = playbook_root

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        if not SAFE_TARGET.match(host.name):
            raise ValueError(
                f"unsafe ansible --limit host {host.name!r}: must start alphanumeric "
                "(option-injection guard, BL-081)"
            )
        # action is the playbook path, confined to the configured root (BL-081).
        playbook = confine_to_root(action, root=self.playbook_root, kind="playbook")
        argv = ["ansible-playbook", playbook, "--limit", host.name]
        if dry_run:
            argv.append("--check")
        return argv
