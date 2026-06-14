"""CIS collector: normalize captured CIS evidence into observed facts (BL-099, ADR-0024).

The evidence is a JSON document an out-of-process T0 read produced (talosctl/API and
sysctl reads run by the operator's CIS automation); this collector only normalizes
it, treating it as untrusted data (SEC-4). It emits one ``OBSERVED`` fact per control
under the schema ADR-0024 fixes: predicate ``cis:<benchmark>:<control_id>`` and value
``{"value": <normalized>}`` using the same normalization as the baseline, so a
compliant node compares equal.

Evidence shape (either form, ``benchmark`` optional, defaults to ``talos``)::

    {"benchmark": "talos", "controls": {"kubelet-anonymous-auth": false, ...}}
    {"benchmark": "talos", "kubelet-anonymous-auth": false, ...}

Only controls present in the active baseline are emitted: evidence for a suppressed,
Talos-satisfied, or unknown control is dropped, so a waived control never reappears as
drift and the observed set stays a subset of the desired set. Malformed input yields
no facts rather than raising.
"""

from __future__ import annotations

import json
from typing import ClassVar

from praxis.collectors.base import Collector
from praxis.drift.cis import CIS_BENCHMARK_DEFAULT, active_control_keys, normalize_value
from praxis.model.facts import Fact


class CisCollector(Collector):
    name: ClassVar[str] = "cis"

    def __init__(self, benchmark: str = CIS_BENCHMARK_DEFAULT) -> None:
        self.benchmark = benchmark

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            # parse_constant maps a JSON NaN/Infinity literal to None rather than a
            # non-finite float, so evidence cannot inject a NaN (BL-026).
            parsed = json.loads(raw, parse_constant=lambda _const: None)
        except (json.JSONDecodeError, RecursionError):
            return []
        if not isinstance(parsed, dict):
            return []

        declared = parsed.get("benchmark")
        benchmark = declared if isinstance(declared, str) and declared else self.benchmark
        controls = parsed.get("controls")
        items = controls if isinstance(controls, dict) else parsed

        active = active_control_keys()
        facts: list[Fact] = []
        for control_id, value in items.items():
            if not isinstance(control_id, str) or control_id == "benchmark":
                continue
            if f"{benchmark}:{control_id}" not in active:
                continue
            facts.append(
                self._fact(
                    subject,
                    f"cis:{benchmark}:{control_id}",
                    {"value": normalize_value(value)},
                    actor,
                )
            )
        return facts
