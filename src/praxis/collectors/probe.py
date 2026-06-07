"""Generic command-probe collector: parse KEY=VALUE / key: value telemetry.

Covers the common shape produced by simple SSH/WinRM probes (for example
``/etc/os-release``, ``sysctl`` dumps, or a ``Get-ComputerInfo`` projection). The
Linux/Windows/cloud collectors reuse this shape; richer per-tool parsing is added
as those paths deepen (see LIMITATIONS). Untrusted output is parsed defensively.
"""

from __future__ import annotations

from typing import ClassVar

from praxis.collectors.base import Collector
from praxis.model.facts import Fact


class CommandProbeCollector(Collector):
    name: ClassVar[str] = "probe"

    def __init__(self, predicate: str) -> None:
        self.predicate = predicate

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        data: dict[str, object] = {}
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, _, val = stripped.partition("=")
                data[key.strip()] = val.strip().strip('"')
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                data[key.strip()] = val.strip()
        return [self._fact(subject, self.predicate, data, actor)]
