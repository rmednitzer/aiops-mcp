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


class TalosCollector(Collector):
    name: ClassVar[str] = "talos"

    def __init__(self, predicate: str) -> None:
        self.predicate = predicate

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return [self._fact(subject, self.predicate, {"status": raw}, actor)]
        if isinstance(parsed, list):
            items = [item for item in parsed if isinstance(item, dict)]
            value: dict[str, object] = {"items": items, "count": len(items)}
        elif isinstance(parsed, dict):
            value = parsed
        else:
            value = {"value": parsed}
        return [self._fact(subject, self.predicate, value, actor)]
