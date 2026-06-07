"""The store contract: a narrow L1 Protocol plus an extension ladder (ADR-0002).

Service code depends only on ``StoreProtocol``. Optional capabilities (vector
search, graph traversal) are separate Protocols a backend implements only if it
can honour them; a backend never fakes an unsupported capability. The L1 surface
intentionally has no ``delete``: facts are append-only (ADR-0003; SEC-10).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from praxis.model.facts import Capability, Edge, Fact


@runtime_checkable
class StoreProtocol(Protocol):
    """The L1 store surface. Append-only, bitemporal (ADR-0002, ADR-0003)."""

    def put_fact(self, fact: Fact) -> Fact:
        """Record a fact. Supersedes the prior active fact for the same key.

        Returns the stored fact with ``fact_id`` and ``t_recorded`` assigned. The
        fact's ``actor`` (and optional ``reason``) provide write provenance.
        """
        ...

    def supersede(
        self, subject: str, predicate: str, fact_type: str, *, actor: str, reason: str
    ) -> Fact | None:
        """Invalidate the active fact for a key without a replacement.

        Requires a non-empty ``actor`` and ``reason`` (SEC-10). Returns the
        invalidated fact, or None if no active fact existed.
        """
        ...

    def get_active(self, subject: str, predicate: str, fact_type: str) -> Fact | None:
        """Return the single active fact for a key, or None."""
        ...

    def list_active(
        self, *, subject: str | None = None, fact_type: str | None = None
    ) -> list[Fact]:
        """Return all active facts, optionally filtered by subject and/or type."""
        ...

    def history(
        self, subject: str, predicate: str | None = None, fact_type: str | None = None
    ) -> list[Fact]:
        """Return every recorded fact for a subject in recorded order (oldest first)."""
        ...

    def put_edge(self, edge: Edge) -> Edge:
        """Record a directed edge. Supersedes the prior active edge for the same key."""
        ...

    def edges_from(self, subject: str, relation: str | None = None) -> list[Edge]:
        """Return active edges originating at ``subject``."""
        ...

    def capabilities(self) -> frozenset[Capability]:
        """The optional capabilities this backend honours."""
        ...

    def close(self) -> None: ...


@runtime_checkable
class VectorStore(Protocol):
    """Optional nearest-neighbour search over fact embeddings (Capability.VECTOR)."""

    def upsert_embedding(self, fact_id: str, vector: Sequence[float]) -> None: ...

    def similar(self, vector: Sequence[float], *, k: int = 10) -> list[tuple[str, float]]:
        """Return up to ``k`` (fact_id, score) pairs, most similar first."""
        ...
