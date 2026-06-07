"""Runbook actuation adapter: run an operator shell script as a subprocess.

DRY_RUN is a non-executing preview (runbooks are not assumed idempotent). The
script path and arguments come from the caller; the executor classifies and gates
the resulting command like any other (ADR-0005).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType


class RunbookAdapter(ActuationAdapter):
    name: ClassVar[str] = "runbook"
    supported: ClassVar[frozenset[HostType]] = frozenset(
        {HostType.UBUNTU, HostType.WINDOWS, HostType.CLOUD}
    )
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        argv = ["bash", action]
        extra = params.get("args")
        if isinstance(extra, list):
            argv += [str(item) for item in extra]
        return argv
