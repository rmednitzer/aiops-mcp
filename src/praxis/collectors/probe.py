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

    # Defense-in-depth caps on untrusted probe output (BL-108, invariant 8). The 4 MiB
    # tool-output ceiling bounds the raw string, but a hostile probe could still emit a
    # huge number of pairs or a single enormous value within it. Bound both the pair
    # count and per key/value length, truncating silently to stay within the
    # never-raises collector contract.
    _MAX_PAIRS: ClassVar[int] = 4096
    _MAX_KEY_LEN: ClassVar[int] = 256
    _MAX_VALUE_LEN: ClassVar[int] = 8192

    def __init__(self, predicate: str) -> None:
        self.predicate = predicate

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        data: dict[str, object] = {}
        for line in raw.splitlines():
            if len(data) >= self._MAX_PAIRS:
                break  # pair-count cap reached; drop the rest silently (BL-108)
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                key, _, val = stripped.partition("=")
                data[key.strip()[: self._MAX_KEY_LEN]] = val.strip().strip('"')[
                    : self._MAX_VALUE_LEN
                ]
            elif ":" in stripped:
                key, _, val = stripped.partition(":")
                data[key.strip()[: self._MAX_KEY_LEN]] = val.strip()[: self._MAX_VALUE_LEN]
        return [self._fact(subject, self.predicate, data, actor)]
