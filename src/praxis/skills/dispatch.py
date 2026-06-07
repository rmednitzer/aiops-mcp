"""Routing-chain dispatcher: select a skill from a query (ADR-0010).

A chain of matchers, cheap first: an exact name/alias match, then a lexical
overlap against each skill's name and description. Per-link failure containment: a
matcher that raises is skipped, never aborting the route (the BL fan-out class
applied to routing). The result is a ranked, deduplicated list.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from praxis.skills.manifest import SkillManifest

_WORD = re.compile(r"[a-z0-9]+")
_STOP = frozenset(
    {"the", "a", "an", "of", "to", "for", "on", "in", "and", "or", "is", "how", "do", "i", "my"}
)


def _tokens(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP}


@dataclass(frozen=True)
class Match:
    name: str
    score: float


class RoutingChainDispatcher:
    def __init__(self, manifests: list[SkillManifest]) -> None:
        self._manifests = manifests

    def route(self, query: str) -> list[Match]:
        matchers: tuple[Callable[[str], list[Match]], ...] = (self._exact, self._lexical)
        best: dict[str, float] = {}
        for matcher in matchers:
            try:
                results = matcher(query)
            except Exception:  # noqa: BLE001, S112 - per-link containment; one bad matcher must not abort
                continue
            for match in results:
                if match.score > best.get(match.name, 0.0):
                    best[match.name] = match.score
        ranked = sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))
        return [Match(name, score) for name, score in ranked if score > 0.0]

    def best(self, query: str) -> str | None:
        ranked = self.route(query)
        return ranked[0].name if ranked else None

    def _exact(self, query: str) -> list[Match]:
        q = query.strip().lower()
        out: list[Match] = []
        for manifest in self._manifests:
            name = manifest.name.lower()
            if q == name:
                out.append(Match(manifest.name, 1.0))
            elif name in q or name.replace("-", " ") in q:
                out.append(Match(manifest.name, 0.9))
        return out

    def _lexical(self, query: str) -> list[Match]:
        query_terms = _tokens(query)
        if not query_terms:
            return []
        out: list[Match] = []
        for manifest in self._manifests:
            terms = _tokens(f"{manifest.name} {manifest.description}")
            overlap = query_terms & terms
            if overlap:
                # Normalize by query length so a fully-covered query scores high but
                # stays below an exact name match.
                out.append(Match(manifest.name, 0.85 * len(overlap) / len(query_terms)))
        return out
