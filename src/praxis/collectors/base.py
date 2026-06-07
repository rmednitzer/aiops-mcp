"""Collector base: parse read-only telemetry into bitemporal fact envelopes.

A collector is a pure parser: given raw tool output (captured by a T0 read through
the executor, or a fixture in tests), it returns a list of ``Fact`` objects ready
for the store. Collectors never run commands themselves and never actuate; the
executor runs the read, the collector only normalizes. All collected output is
attacker-influenced and is treated as data, never as instructions (SEC-4).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from praxis.clock import utc_now_iso
from praxis.model.facts import OBSERVED, Fact


class Collector(ABC):
    """Normalizes one tool's raw output into observed facts about a subject."""

    name: ClassVar[str]
    fact_type: ClassVar[str] = OBSERVED

    @abstractmethod
    def parse(self, raw: str, *, subject: str, actor: str = "collector") -> list[Fact]:
        """Parse raw output into facts about ``subject``. Pure; never raises on
        malformed input beyond returning fewer facts."""
        ...

    def _fact(self, subject: str, predicate: str, value: dict[str, object], actor: str) -> Fact:
        return Fact(
            subject=subject,
            predicate=predicate,
            fact_type=self.fact_type,
            value=value,
            t_valid=utc_now_iso(),
            actor=actor,
        )
