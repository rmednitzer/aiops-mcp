"""Bitemporal fact and edge types, and the host_type enum (ADR-0003).

Every fact carries four timestamps (ADR-0003):

- ``t_valid``: when the fact became true in the world.
- ``t_invalid``: when it stopped being true in the world (None while active).
- ``t_recorded``: when the store recorded it (assigned by the store).
- ``t_superseded``: when the store replaced this record (None while current).

A fact is keyed by ``(subject, predicate, fact_type)``; at most one row per key is
active. "Active" means ``t_invalid is None and t_superseded is None``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Literal

# Common fact types. The store does not constrain the string, but these are the
# vocabulary the drift engine and collectors use.
OBSERVED = "observed"
DESIRED = "desired"
DRIFT = "drift"
KNOWN_GOOD = "known_good"

FactType = Literal["observed", "desired", "drift", "known_good"]


class HostType(Enum):
    """The actuation paradigm of a host. Gates which adapter is legal (SEC-5)."""

    UBUNTU = "ubuntu"  # ssh / ansible / runbook
    TALOS = "talos"  # talosctl only; NEVER ssh (immutable, API-only)
    WINDOWS = "windows"  # winrm / ssh
    CLOUD = "cloud"  # cloud API / redfish OOB


class Capability(Enum):
    """Optional store capabilities advertised via ``StoreProtocol.capabilities``."""

    VECTOR = "vector"  # nearest-neighbour search over embeddings
    GRAPH = "graph"  # native multi-hop graph traversal
    BATCH = "batch"  # batched writes


@dataclass(frozen=True)
class Fact:
    """A bitemporal fact about a subject (a vertex attribute)."""

    subject: str
    predicate: str
    fact_type: str
    value: dict[str, object]
    t_valid: str
    actor: str
    reason: str | None = None
    t_invalid: str | None = None
    t_recorded: str | None = None
    t_superseded: str | None = None
    fact_id: str | None = None

    @property
    def is_active(self) -> bool:
        return self.t_invalid is None and self.t_superseded is None

    def key(self) -> tuple[str, str, str]:
        return (self.subject, self.predicate, self.fact_type)


@dataclass(frozen=True)
class Edge:
    """A bitemporal directed edge between two vertices."""

    subject: str
    relation: str
    target: str
    value: dict[str, object] = field(default_factory=dict)
    t_valid: str = ""
    actor: str = "system"
    reason: str | None = None
    t_invalid: str | None = None
    t_recorded: str | None = None
    t_superseded: str | None = None
    edge_id: str | None = None

    @property
    def is_active(self) -> bool:
        return self.t_invalid is None and self.t_superseded is None

    def key(self) -> tuple[str, str, str]:
        return (self.subject, self.relation, self.target)


def with_recorded(fact: Fact, *, fact_id: str, t_recorded: str) -> Fact:
    """Return a copy of ``fact`` stamped with its store-assigned identity."""
    return replace(fact, fact_id=fact_id, t_recorded=t_recorded)
