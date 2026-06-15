"""The store contract: a narrow L1 Protocol plus an extension ladder (ADR-0002).

Service code depends only on ``StoreProtocol``. Optional capabilities (vector
search, graph traversal) are separate Protocols a backend implements only if it
can honour them; a backend never fakes an unsupported capability. The L1 surface
intentionally has no ``delete``: facts are append-only (ADR-0003; SEC-10).
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from typing import Any, Concatenate, Protocol, cast, runtime_checkable

from praxis.model.facts import Capability, Edge, Fact


def synchronized[**P, R](
    method: Callable[Concatenate[Any, P], R],
) -> Callable[Concatenate[Any, P], R]:
    """Serialise a store method on the instance's ``_lock`` (BL-110, ADR-0042).

    A single shared store connection (one ``sqlite3`` / ``psycopg`` connection) is not
    safe for concurrent use across threads, so the multi-threaded HTTP transport
    serialises every connection-touching method on a per-instance re-entrant lock.
    ``RLock`` so a method that calls another locked method on the same instance
    (``put_fact`` -> ``get_active``) re-enters on the same thread. The slow work the
    threaded server parallelises (actuation subprocesses, network I/O) runs outside any
    store method, so serialising the fast store operations costs no actuation
    concurrency while keeping the bitemporal/append-only invariants intact.
    """

    @functools.wraps(method)
    def wrapper(self: Any, *args: P.args, **kwargs: P.kwargs) -> R:
        with self._lock:
            return method(self, *args, **kwargs)

    # functools.wraps yields a _Wrapped type whose named ``self`` arg mypy will not unify
    # with the positional ``Any`` here; the call signature is identical, so cast back.
    return cast("Callable[Concatenate[Any, P], R]", wrapper)


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


class VersionConflict(Exception):
    """A compare-and-set write whose expected version did not match the active fact.

    Raised by ``VersionedStore.put_fact_if`` when the current active fact's
    ``content_hash`` differs from the caller's ``expected_version`` (or an active
    fact exists when ``None`` was expected). Nothing is written: the caller read a
    now-stale fact and must re-read before deciding again (BL-027; ADR-0021).
    """


@runtime_checkable
class VersionedStore(Protocol):
    """Optional content-hash compare-and-set over the active fact (Capability.COMPARE_AND_SET).

    The version token is ``Fact.content_hash()``. ``put_fact_if`` makes the
    read-compare-write atomic AND version-gated, so a lost update is impossible: an
    operator who approves replacing the fact they read cannot have that approval
    silently applied to a different value that landed in between (the human-gated
    convergence guarantee, SEC-6). A backend implements this only if it can hold an
    exclusive lock across the read and the write; it never fakes it.
    """

    def put_fact_if(self, fact: Fact, *, expected_version: str | None) -> Fact:
        """Record ``fact``, superseding the active fact for its key, only if that
        active fact's ``content_hash`` equals ``expected_version`` (or no active fact
        exists when ``expected_version`` is None). Raises ``VersionConflict`` and
        writes nothing otherwise. Atomic: the compare and the write share one
        exclusive transaction."""
        ...
