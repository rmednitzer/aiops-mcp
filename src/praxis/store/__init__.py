"""The pluggable bitemporal store (ADR-0002).

``StoreProtocol`` is the L1 surface every backend honours. ``open_store`` selects a
backend from a DSN: SQLite (the default, no external services) or Postgres+AGE
(production, lazy-imported). Optional capabilities (vector, graph) are advertised
via ``capabilities`` and reached through extension Protocols (`VectorStore`).
"""

from __future__ import annotations

from praxis.store.base import StoreProtocol, VectorStore
from praxis.store.sqlite import SqliteStore


def open_store(dsn: str | None = None) -> StoreProtocol:
    """Open a store from a DSN.

    - ``None``, ``":memory:"``, ``sqlite:///path``, or a bare path -> SQLite.
    - ``postgresql://...`` or ``postgres://...`` -> Postgres+AGE (requires the
      ``postgres`` extra; raises a clear error if the driver is absent).
    """
    if dsn is None or dsn == ":memory:":
        return SqliteStore(":memory:")
    if dsn.startswith(("postgresql://", "postgres://")):
        from praxis.store.postgres import PostgresStore  # lazy: optional dependency

        return PostgresStore(dsn)
    if dsn.startswith("sqlite:///"):
        return SqliteStore(dsn.removeprefix("sqlite:///"))
    return SqliteStore(dsn)


__all__ = ["SqliteStore", "StoreProtocol", "VectorStore", "open_store"]
