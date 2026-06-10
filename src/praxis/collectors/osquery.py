"""osquery collector: parse ``osqueryi --json`` result sets into facts (BL-007).

osquery returns a JSON array of row dicts for a query. This collector emits one
fact per configured query, with the rows preserved under the given predicate, so a
host's packages, listening ports, kernel modules, and so on become queryable
facts. Malformed JSON yields no facts rather than raising.
"""

from __future__ import annotations

import json
from typing import ClassVar

from praxis.collectors.base import Collector
from praxis.model.facts import Fact


class OsqueryCollector(Collector):
    name: ClassVar[str] = "osquery"

    def __init__(self, predicate: str) -> None:
        self.predicate = predicate

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        try:
            # parse_constant maps a JSON NaN/Infinity/-Infinity literal to None
            # rather than a non-finite float, so collected telemetry cannot inject a
            # NaN that later poisons numeric comparisons or vector ranking (BL-026).
            parsed = json.loads(raw, parse_constant=lambda _const: None)
        except (json.JSONDecodeError, RecursionError):
            return []
        rows = parsed if isinstance(parsed, list) else []
        clean_rows = [row for row in rows if isinstance(row, dict)]
        value: dict[str, object] = {"rows": clean_rows, "count": len(clean_rows)}
        return [self._fact(subject, self.predicate, value, actor)]
