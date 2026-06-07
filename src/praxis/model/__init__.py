"""The fleet-state model: bitemporal fact types, the edge schema, and host_type.

See ADR-0003 (bitemporal fact model). Facts and edges are append-only; the store
(ADR-0002) enforces that at the storage layer.
"""

from __future__ import annotations

from praxis.model.facts import (
    DESIRED,
    DRIFT,
    KNOWN_GOOD,
    OBSERVED,
    Capability,
    Edge,
    Fact,
    FactType,
    HostType,
    with_recorded,
)

__all__ = [
    "DESIRED",
    "DRIFT",
    "KNOWN_GOOD",
    "OBSERVED",
    "Capability",
    "Edge",
    "Fact",
    "FactType",
    "HostType",
    "with_recorded",
]
