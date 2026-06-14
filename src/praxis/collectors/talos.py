"""Talos collector: parse ``talosctl ... -o json`` resources into facts (BL-007).

Talos is API-only: telemetry comes from ``talosctl get <resource> -o json`` and
``talosctl health``, never from a shell on the node (SEC-5; host_type=talos). This
collector normalizes the JSON resource form; non-JSON (for example a health text
line) degrades to a single status fact.
"""

from __future__ import annotations

import json
from typing import ClassVar

from praxis.collectors.base import Collector
from praxis.model.facts import Fact

# Cap on the non-JSON status fallback (F-008): a hostile or malfunctioning node could
# return megabytes of non-JSON text, and the bitemporal fact store must not accept an
# unbounded attacker-controlled blob every collection cycle (invariant 8). The cap is
# generous for a real status line; oversized text is truncated with a visible marker.
_MAX_STATUS_CHARS = 4096


class TalosCollector(Collector):
    name: ClassVar[str] = "talos"

    def __init__(self, predicate: str) -> None:
        self.predicate = predicate

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            # parse_constant maps a JSON NaN/Infinity literal to None rather than a
            # non-finite float, so collected telemetry cannot inject a NaN (BL-026).
            parsed = json.loads(raw, parse_constant=lambda _const: None)
        except (json.JSONDecodeError, RecursionError):
            status = (
                raw if len(raw) <= _MAX_STATUS_CHARS else raw[:_MAX_STATUS_CHARS] + "...[truncated]"
            )
            return [self._fact(subject, self.predicate, {"status": status}, actor)]
        if isinstance(parsed, list):
            items = [item for item in parsed if isinstance(item, dict)]
            value: dict[str, object] = {"items": items, "count": len(items)}
        elif isinstance(parsed, dict):
            value = parsed
        else:
            value = {"value": parsed}
        return [self._fact(subject, self.predicate, value, actor)]
