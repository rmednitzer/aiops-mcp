"""Drift findings: structured observed-vs-desired deltas, recordable as facts.

A finding is the unit of drift. It is written into the store as a bitemporal fact
(fact_type=drift), so drift has history: when it appeared and when it cleared
(ADR-0007; L-5).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from praxis.clock import utc_now_iso
from praxis.model.facts import DRIFT, Fact


class DriftKind(Enum):
    MISSING = "missing"  # desired exists, observed does not
    UNEXPECTED = "unexpected"  # observed exists, desired does not
    CHANGED = "changed"  # both exist, values differ


class DriftSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass(frozen=True)
class DriftFinding:
    subject: str
    predicate: str
    kind: DriftKind
    severity: DriftSeverity
    observed: dict[str, object] | None
    desired: dict[str, object] | None

    def to_fact(self, *, actor: str = "drift-engine") -> Fact:
        value: dict[str, object] = {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "observed": self.observed,
            "desired": self.desired,
        }
        return Fact(
            subject=self.subject,
            predicate=f"drift:{self.predicate}",
            fact_type=DRIFT,
            value=value,
            t_valid=utc_now_iso(),
            actor=actor,
        )
