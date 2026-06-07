"""AIDE collector: parse an ``aide --check`` report into a file-integrity fact.

AIDE reports added, removed, and changed filesystem entries against its baseline.
This collector parses the summary and the entry lists into a single
``file_integrity`` fact, which the drift engine compares against the desired
(clean) baseline. Output is untrusted; parsing is defensive (SEC-4).
"""

from __future__ import annotations

import re
from typing import ClassVar

from praxis.collectors.base import Collector
from praxis.model.facts import Fact

_SUMMARY = re.compile(
    r"Total number of entries:\s*(?P<total>\d+).*?"
    r"Added entries:\s*(?P<added>\d+).*?"
    r"Removed entries:\s*(?P<removed>\d+).*?"
    r"Changed entries:\s*(?P<changed>\d+)",
    re.IGNORECASE | re.DOTALL,
)
_SECTION = re.compile(r"^(Added|Removed|Changed)\s+entries:\s*$", re.IGNORECASE)
_ENTRY = re.compile(r"(?P<path>/\S+)")


class AideCollector(Collector):
    name: ClassVar[str] = "aide"

    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        summary = _SUMMARY.search(raw)
        added, removed, changed = self._collect_paths(raw)
        has_diff = bool(added or removed or changed)
        # A run is "complete" only if it produced a parseable summary or at least an
        # entry section. Empty or unparseable output (a failed probe, a timeout) is
        # NOT a clean host: a clean verdict requires positive evidence of a finished
        # run, never the mere absence of parsed diffs, so a broken collector cannot
        # masquerade as file-integrity-clean (BL-058).
        complete = summary is not None or has_diff
        value: dict[str, object] = {
            "added": added,
            "removed": removed,
            "changed": changed,
            "complete": complete,
            "clean": complete and not has_diff,
        }
        if summary is not None:
            value["totals"] = {
                "total": int(summary.group("total")),
                "added": int(summary.group("added")),
                "removed": int(summary.group("removed")),
                "changed": int(summary.group("changed")),
            }
        return [self._fact(subject, "file_integrity", value, actor)]

    @staticmethod
    def _collect_paths(raw: str) -> tuple[list[str], list[str], list[str]]:
        buckets: dict[str, list[str]] = {"added": [], "removed": [], "changed": []}
        current: str | None = None
        for line in raw.splitlines():
            section = _SECTION.match(line.strip())
            if section is not None:
                current = section.group(1).lower()
                continue
            if current is None:
                continue
            if not line.strip():
                current = None
                continue
            entry = _ENTRY.search(line)
            if entry is not None:
                buckets[current].append(entry.group("path"))
        return buckets["added"], buckets["removed"], buckets["changed"]
