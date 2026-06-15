"""OpenTofu actuation adapter. DRY_RUN maps to a native ``tofu plan``.

The operator approval is enforced by the executor's T2/T3 gate (ADR-0005), so the
real apply runs non-interactively (``-auto-approve``); the human gate is upstream
of tofu, not tofu's own prompt.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo, confine_to_root
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class OpenTofuAdapter(ActuationAdapter):
    name: ClassVar[str] = "opentofu"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU, HostType.CLOUD})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = True  # tofu plan is a safe preview

    def __init__(self, *, tofu_root: str | None = None) -> None:
        # The only directory a `-chdir` workspace may resolve under (PRAXIS_TOFU_ROOT).
        # None refuses any chdir outright: fail closed (BL-105).
        self.tofu_root = tofu_root

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        # Workspace selection (`-chdir`) is confined to PRAXIS_TOFU_ROOT, the same
        # fail-closed pattern as the ansible/runbook roots (BL-105; the unconfined
        # passthrough was removed as F-003). With no chdir requested the behaviour is
        # unchanged; a chdir without a configured root is refused by confine_to_root.
        # `-chdir` is a global flag and MUST precede the subcommand.
        prefix = ["tofu"]
        chdir = params.get("chdir")
        if chdir is not None:
            workspace = confine_to_root(str(chdir), root=self.tofu_root, kind="tofu", require="dir")
            prefix.append(f"-chdir={workspace}")
        if dry_run:
            # A full plan, not -refresh-only: the preview must show exactly the
            # changes the subsequent apply would make (invariant 6), not merely
            # the drift a refresh detects. -refresh-only belongs to the drift
            # engine (drift/sources.py), not to the actuation dry-run. (BL-043)
            return [*prefix, "plan"]
        return [*prefix, "apply", "-auto-approve"]
