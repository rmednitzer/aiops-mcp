"""Store round-trip, active-fact uniqueness, edges, and vector search."""

from __future__ import annotations

import json
import math

import pytest

from praxis.model import OBSERVED, Capability, Edge, Fact
from praxis.store import SqliteStore, open_store


def _os_fact(version: str) -> Fact:
    return Fact(
        subject="host:axiom",
        predicate="os_version",
        fact_type=OBSERVED,
        value={"name": "Ubuntu", "version": version},
        t_valid="2026-06-07T00:00:00.000000Z",
        actor="collector",
    )


def test_put_and_get_active() -> None:
    store = SqliteStore()
    stored = store.put_fact(_os_fact("24.04"))
    assert stored.fact_id is not None
    assert stored.t_recorded is not None
    got = store.get_active("host:axiom", "os_version", OBSERVED)
    assert got is not None
    assert got.value == {"name": "Ubuntu", "version": "24.04"}
    assert got.is_active is True


def test_one_active_fact_per_key() -> None:
    store = SqliteStore()
    store.put_fact(_os_fact("22.04"))
    store.put_fact(_os_fact("24.04"))  # supersedes the prior active fact
    active = store.get_active("host:axiom", "os_version", OBSERVED)
    assert active is not None
    assert active.value["version"] == "24.04"
    assert len(store.list_active(subject="host:axiom")) == 1
    assert len(store.history("host:axiom", "os_version")) == 2


def test_edges_roundtrip() -> None:
    store = SqliteStore()
    store.put_edge(
        Edge(subject="host:axiom", relation="runs", target="service:nginx", actor="collector")
    )
    edges = store.edges_from("host:axiom")
    assert len(edges) == 1
    assert edges[0].target == "service:nginx"
    assert edges[0].is_active is True


def test_open_store_defaults_to_sqlite() -> None:
    store = open_store()
    assert Capability.VECTOR in store.capabilities()


def test_vector_search_orders_by_similarity() -> None:
    store = SqliteStore()
    store.upsert_embedding("f_x", [1.0, 0.0])
    store.upsert_embedding("f_y", [0.0, 1.0])
    result = store.similar([0.9, 0.1], k=1)
    assert result[0][0] == "f_x"


def test_vector_search_skips_non_finite_stored_vector() -> None:
    # A corrupted/poisoned embedding (NaN component) must not rank; it is skipped
    # rather than dragging a NaN score into the ordering (BL-054).
    store = SqliteStore()
    store.upsert_embedding("good", [1.0, 0.0])
    # Write a NaN-bearing vector directly (json.dumps emits NaN, json.loads reads it).
    store._conn.execute(
        "INSERT INTO embeddings (fact_id, vector) VALUES (?, ?)",
        ("poison", json.dumps([math.nan, 1.0])),
    )
    result = store.similar([0.9, 0.1], k=10)
    names = {fact_id for fact_id, _ in result}
    assert "good" in names
    assert "poison" not in names


def test_vector_search_rejects_non_finite_query() -> None:
    store = SqliteStore()
    store.upsert_embedding("good", [1.0, 0.0])
    with pytest.raises(ValueError, match="finite"):
        store.similar([math.inf, 0.0])
