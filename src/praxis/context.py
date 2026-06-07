"""ServerContext: per-session state, the trifecta gate, and classification filtering.

The lethal-trifecta containment (SEC-4, invariant 8): once a session has ingested
attacker-influenced content (a collector read, a feed), actuation in that session
requires the human gate. ``guard_actuation`` refuses any act (tier >= T1) without an
approval once untrusted content is in play, so injected instructions in collected
data cannot drive an action on their own. Read tools and act tools stay separable.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionContext
from praxis.store.base import StoreProtocol

_RESTRICTED = "restricted"


def _is_restricted(row: dict[str, object]) -> bool:
    if row.get("classification") == _RESTRICTED:
        return True
    value = row.get("value")
    return isinstance(value, dict) and value.get("classification") == _RESTRICTED


class TrifectaViolation(Exception):
    """Raised when actuation is attempted in a session that holds untrusted content
    without a human gate (SEC-4)."""


@dataclass
class ServerContext:
    execution: ExecutionContext
    store: StoreProtocol
    transport: str = "stdio"
    allow_restricted: bool = True
    untrusted_ingested: bool = field(default=False)

    def mark_untrusted_ingested(self) -> None:
        """Record that attacker-influenced content has entered this session."""
        self.untrusted_ingested = True

    def guard_actuation(self, *, tier: Tier, approved: bool) -> None:
        """Enforce the trifecta gate before an act tool runs (SEC-4).

        Once untrusted content is in the session, any actuation needs the human
        gate (an approval). Without ingestion, the executor's own tier gate applies
        and this is a no-op.
        """
        if self.untrusted_ingested and tier >= Tier.T1 and not approved:
            raise TrifectaViolation(
                "this session has ingested untrusted content; actuation requires a "
                "human approval (lethal-trifecta containment, SEC-4)"
            )

    def filter_restricted(self, rows: list[dict[str, object]]) -> list[dict[str, object]]:
        """Drop classification=restricted rows over a transport that may not see
        them (HTTP, unless explicitly allowed). Mirrors the isms-mcp pattern.

        Classification may sit at the row level or nested inside the fact ``value``
        dict (the shape the state tools emit), so both are checked.
        """
        if self.allow_restricted:
            return rows
        return [row for row in rows if not _is_restricted(row)]
