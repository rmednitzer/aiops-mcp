"""Shared store-behavior parity across backends (BL-061).

The same behavioral assertions run against SQLite (always) and Postgres (when
``PRAXIS_TEST_PG_DSN`` names a live database), so the two backends cannot drift
apart on the bitemporal semantics the model relies on (ADR-0002, ADR-0003,
invariant 4). Backend-specific mechanics (file modes, SQL trigger text, seq
uniqueness internals) stay in their per-backend test modules.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from praxis.model.facts import OBSERVED, Capability, Edge, Fact
from praxis.store import SqliteStore
from praxis.store.base import StoreProtocol, VersionConflict, VersionedStore

PG_DSN = os.environ.get("PRAXIS_TEST_PG_DSN")


@pytest.fixture(params=["sqlite", "postgres"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[StoreProtocol]:
    if request.param == "sqlite":
        backend: StoreProtocol = SqliteStore(tmp_path / "parity.db")
    else:
        pytest.importorskip("psycopg")
        if not PG_DSN:
            pytest.skip("set PRAXIS_TEST_PG_DSN to run Postgres parity tests")
        from praxis.store.postgres import PostgresStore

        backend = PostgresStore(PG_DSN)
    yield backend
    backend.close()


def _subject() -> str:
    # Unique per test run: the Postgres database persists across runs.
    return f"host:parity-{uuid.uuid4().hex[:10]}"


def _fact(subject: str, predicate: str, value: str) -> Fact:
    return Fact(
        subject=subject,
        predicate=predicate,
        fact_type=OBSERVED,
        value={"v": value},
        t_valid="2026-06-12T00:00:00.000000Z",
        actor="parity-test",
    )


def test_roundtrip_preserves_value_and_provenance(store: StoreProtocol) -> None:
    subject = _subject()
    stored = store.put_fact(_fact(subject, "os", "ubuntu-24.04"))
    assert stored.fact_id is not None
    got = store.get_active(subject, "os", OBSERVED)
    assert got is not None
    assert got.value == {"v": "ubuntu-24.04"}
    assert got.actor == "parity-test"
    assert got.t_recorded is not None


def test_put_supersedes_prior_active_fact(store: StoreProtocol) -> None:
    # ADR-0003: one active fact per (subject, predicate, fact_type); a new put
    # supersedes the old row, never duplicates or deletes it.
    subject = _subject()
    store.put_fact(_fact(subject, "kernel", "6.17"))
    store.put_fact(_fact(subject, "kernel", "6.18"))
    active = store.get_active(subject, "kernel", OBSERVED)
    assert active is not None
    assert active.value == {"v": "6.18"}
    history = store.history(subject, "kernel")
    assert len(history) == 2
    superseded = [f for f in history if f.t_superseded is not None]
    assert len(superseded) == 1
    assert superseded[0].value == {"v": "6.17"}


def test_supersede_records_actor_and_reason(store: StoreProtocol) -> None:
    # Invariant 4: retirement carries provenance; the original row survives.
    subject = _subject()
    store.put_fact(_fact(subject, "role", "worker"))
    retired = store.supersede(subject, "role", OBSERVED, actor="operator", reason="decommissioned")
    assert retired is not None
    assert retired.t_superseded is not None
    assert retired.t_invalid is not None
    assert store.get_active(subject, "role", OBSERVED) is None
    assert len(store.history(subject, "role")) == 1


def test_supersede_requires_actor_and_reason(store: StoreProtocol) -> None:
    subject = _subject()
    store.put_fact(_fact(subject, "p", "v"))
    with pytest.raises(ValueError, match="actor"):
        store.supersede(subject, "p", OBSERVED, actor="", reason="r")
    with pytest.raises(ValueError, match="actor|reason"):
        store.supersede(subject, "p", OBSERVED, actor="a", reason="")


def test_put_fact_requires_actor(store: StoreProtocol) -> None:
    fact = _fact(_subject(), "p", "v")
    anonymous = Fact(
        subject=fact.subject,
        predicate=fact.predicate,
        fact_type=fact.fact_type,
        value=fact.value,
        t_valid=fact.t_valid,
        actor="",
    )
    with pytest.raises(ValueError, match="actor"):
        store.put_fact(anonymous)


def test_list_active_filters_subject_and_type(store: StoreProtocol) -> None:
    subject = _subject()
    store.put_fact(_fact(subject, "p1", "a"))
    store.put_fact(_fact(subject, "p2", "b"))
    rows = store.list_active(subject=subject, fact_type=OBSERVED)
    assert {f.predicate for f in rows} == {"p1", "p2"}
    assert store.list_active(subject=subject, fact_type="desired") == []


# ----------------------------------------------------------------- BL-027 (CAS)
def test_compare_and_set_capability_is_advertised(store: StoreProtocol) -> None:
    # A backend that exposes put_fact_if must also advertise the capability, and
    # vice versa: the ladder stays honest (a backend never fakes an unsupported one).
    assert isinstance(store, VersionedStore)
    assert Capability.COMPARE_AND_SET in store.capabilities()


def test_put_fact_if_creates_only_when_absent(store: StoreProtocol) -> None:
    assert isinstance(store, VersionedStore)
    subject = _subject()
    # expected_version=None asserts "no active fact for this key" -> creates it.
    created = store.put_fact_if(_fact(subject, "os", "ubuntu-24.04"), expected_version=None)
    assert created.value == {"v": "ubuntu-24.04"}
    # A second create-if-absent now conflicts: an active fact already exists.
    with pytest.raises(VersionConflict):
        store.put_fact_if(_fact(subject, "os", "ubuntu-26.04"), expected_version=None)
    assert store.get_active(subject, "os", OBSERVED) is not None
    active = store.get_active(subject, "os", OBSERVED)
    assert active is not None and active.value == {"v": "ubuntu-24.04"}  # unchanged


def test_put_fact_if_supersedes_on_matching_version(store: StoreProtocol) -> None:
    assert isinstance(store, VersionedStore)
    subject = _subject()
    first = store.put_fact(_fact(subject, "kernel", "6.17"))
    # The version a caller reads off get_active is the content hash; CAS on it.
    updated = store.put_fact_if(
        _fact(subject, "kernel", "6.18"), expected_version=first.content_hash()
    )
    assert updated.value == {"v": "6.18"}
    active = store.get_active(subject, "kernel", OBSERVED)
    assert active is not None and active.value == {"v": "6.18"}
    # The prior row is superseded, not deleted (invariant 4).
    history = store.history(subject, "kernel")
    assert len(history) == 2
    assert sum(1 for f in history if f.t_superseded is not None) == 1


def test_put_fact_if_rejects_stale_version(store: StoreProtocol) -> None:
    # A lost-update guard: a write whose expected version is no longer the active one
    # is refused and writes nothing, so an approval bound to a stale read cannot land.
    assert isinstance(store, VersionedStore)
    subject = _subject()
    first = store.put_fact(_fact(subject, "role", "worker"))
    stale_version = first.content_hash()
    store.put_fact(_fact(subject, "role", "control-plane"))  # someone else moves it on
    with pytest.raises(VersionConflict):
        store.put_fact_if(_fact(subject, "role", "edge"), expected_version=stale_version)
    active = store.get_active(subject, "role", OBSERVED)
    assert active is not None and active.value == {"v": "control-plane"}  # the CAS wrote nothing
    # History holds exactly the two honest writes, not a third from the rejected CAS.
    assert len(store.history(subject, "role")) == 2


def test_put_fact_if_requires_actor(store: StoreProtocol) -> None:
    # The CAS write path names itself in the provenance error, not put_fact.
    assert isinstance(store, VersionedStore)
    anonymous = Fact(
        subject=_subject(),
        predicate="p",
        fact_type=OBSERVED,
        value={"v": "x"},
        t_valid="2026-06-12T00:00:00.000000Z",
        actor="",
    )
    with pytest.raises(ValueError, match="put_fact_if"):
        store.put_fact_if(anonymous, expected_version=None)


def test_content_hash_is_stable_across_roundtrip(store: StoreProtocol) -> None:
    # The version token must survive the store round-trip identically, or CAS by a
    # caller-computed hash could never match.
    subject = _subject()
    stored = store.put_fact(_fact(subject, "p", "v"))
    reread = store.get_active(subject, "p", OBSERVED)
    assert reread is not None
    assert stored.content_hash() == reread.content_hash()


def test_edge_roundtrip_and_supersede_on_reput(store: StoreProtocol) -> None:
    subject = _subject()
    edge = Edge(
        subject=subject,
        relation="runs_on",
        target="host:hypervisor-1",
        value={"since": "2026-06-12"},
        t_valid="2026-06-12T00:00:00.000000Z",
        actor="parity-test",
    )
    store.put_edge(edge)
    store.put_edge(edge)  # re-put supersedes, never duplicates the active edge
    active = store.edges_from(subject, "runs_on")
    assert len(active) == 1
    assert active[0].target == "host:hypervisor-1"
