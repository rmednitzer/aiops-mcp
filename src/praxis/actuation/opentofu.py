"""OpenTofu actuation adapter. DRY_RUN maps to a native ``tofu plan``.

The operator approval is enforced by the executor's T2/T3 gate (ADR-0005), so the
real apply runs non-interactively (``-auto-approve``); the human gate is upstream
of tofu, not tofu's own prompt.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class OpenTofuAdapter(ActuationAdapter):
    name: ClassVar[str] = "opentofu"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU, HostType.CLOUD})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = True  # tofu plan is a safe preview

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        chdir = params.get("chdir")
        prefix = ["tofu", f"-chdir={chdir}"] if isinstance(chdir, str) else ["tofu"]
        if dry_run:
            # A full plan, not -refresh-only: the preview must show exactly the
            # changes the subsequent apply would make (invariant 6), not merely
            # the drift a refresh detects. -refresh-only belongs to the drift
            # engine (drift/sources.py), not to the actuation dry-run. (BL-043)
            return [*prefix, "plan"]
        return [*prefix, "apply", "-auto-approve"]
