"""ServerContext: per-session state, the trifecta latch, and classification filtering.

The lethal-trifecta containment (SEC-4, invariant 8): once a session has taken in
attacker-influenced content (an ingest, a read that returned observed facts), any
T1+ actuation in that session requires a minted approval. Since ADR-0016 (BL-083)
that gate is enforced INSIDE the single audited path (``execution.runner.run``),
keyed off the session taint latch shared with ``ExecutionContext``; this context
only arms the latch and filters restricted rows. Read tools and act tools stay
separable.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from praxis.actuation.credentials import CredentialBroker
from praxis.execution.runner import ExecutionContext
from praxis.model.facts import OBSERVED, Fact
from praxis.store.base import StoreProtocol

_RESTRICTED = "restricted"


def _is_restricted(row: dict[str, object]) -> bool:
    if row.get("classification") == _RESTRICTED:
        return True
    value = row.get("value")
    return isinstance(value, dict) and value.get("classification") == _RESTRICTED


@dataclass
class ServerContext:
    execution: ExecutionContext
    store: StoreProtocol
    transport: str = "stdio"
    allow_restricted: bool = True
    # Scoped-credential enforcement (BL-049). With zero grants the broker is
    # inert (the single-operator default); the first grant flips actuation to
    # deny-unless-authorized. ``kill_all`` trips the shared kill switch.
    broker: CredentialBroker | None = None

    @property
    def untrusted_ingested(self) -> bool:
        """The session taint latch, shared with the execution core (BL-083)."""
        return self.execution.taint.untrusted_ingested

    def mark_untrusted_ingested(self) -> None:
        """Record that attacker-influenced content has entered this session."""
        self.execution.taint.mark()

    def mark_if_observed(self, facts: Iterable[Fact]) -> None:
        """Arm the latch when a read returns any observed (attacker-influenced) fact.

        The one place that encodes "reading collected data back is as untrusted as
        live collection" (SEC-4, invariant 8), so every read tool applies the same
        rule instead of each re-implementing it (BL-083).
        """
        if any(f.fact_type == OBSERVED for f in facts):
            self.mark_untrusted_ingested()

    def filter_restricted(self, rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Drop classification=restricted rows over a transport that may not see
        them (HTTP, unless explicitly allowed).

        Classification may sit at the row level or nested inside the fact ``value``
        dict (the shape the state tools emit), so both are checked.
        """
        if self.allow_restricted:
            return rows
        return [row for row in rows if not _is_restricted(row)]
