"""Runbook actuation adapter: run an operator shell script as a subprocess.

DRY_RUN is a non-executing preview (runbooks are not assumed idempotent). The
script path is confined to the configured runbook root, fail closed when unset
(BL-024, ADR-0016), so a hostile ``action`` cannot hand ``bash`` an arbitrary
filesystem path. Arguments after the script path are script arguments (bash does
not parse them), and the executor classifies and gates the resulting command like
any other (ADR-0005).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo, confine_to_root
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class RunbookAdapter(ActuationAdapter):
    name: ClassVar[str] = "runbook"
    supported: ClassVar[frozenset[HostType]] = frozenset(
        {HostType.UBUNTU, HostType.WINDOWS, HostType.CLOUD}
    )
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False

    def __init__(self, runbook_root: str | None = None) -> None:
        # The only directory runbooks may run from (PRAXIS_RUNBOOK_ROOT).
        # None refuses every runbook: fail closed (BL-024).
        self.runbook_root = runbook_root

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        script = confine_to_root(action, root=self.runbook_root, kind="runbook")
        argv = ["bash", script]
        extra = params.get("args")
        if isinstance(extra, list):
            argv += [str(item) for item in extra]
        return argv
