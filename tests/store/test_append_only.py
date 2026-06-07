"""SEC-10 / invariant 4: state is append-only; deletion blocked at the storage layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from praxis.model import OBSERVED, Fact
from praxis.store import SqliteStore
from praxis.store.base import StoreProtocol


def _fact(value: dict[str, object], actor: str = "collector") -> Fact:
    return Fact(
        subject="host:axiom",
        predicate="os_version",
        fact_type=OBSERVED,
        value=value,
        t_valid="2026-06-07T00:00:00.000000Z",
        actor=actor,
    )


def test_delete_is_blocked(tmp_path: Path) -> None:
    db = tmp_path / "store.db"
    store = SqliteStore(db)
    store.put_fact(_fact({"version": "24.04"}))
    store.close()

    # A direct DELETE through any connection is refused by the storage-layer trigger,
    # so a buggy or malicious caller cannot erase history (ADR-0003).
    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute("DELETE FROM facts")
            conn.commit()
    finally:
        conn.close()


def test_in_place_value_update_is_blocked(tmp_path: Path) -> None:
    db = tmp_path / "store.db"
    store = SqliteStore(db)
    store.put_fact(_fact({"version": "24.04"}))
    store.close()

    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute('UPDATE facts SET value = \'{"version": "tampered"}\'')
            conn.commit()
    finally:
        conn.close()


def test_supersede_requires_actor_and_reason() -> None:
    store = SqliteStore()
    store.put_fact(_fact({"version": "24.04"}))
    with pytest.raises(ValueError):
        store.supersede("host:axiom", "os_version", OBSERVED, actor="", reason="x")
    with pytest.raises(ValueError):
        store.supersede("host:axiom", "os_version", OBSERVED, actor="operator", reason="")

    invalidated = store.supersede(
        "host:axiom", "os_version", OBSERVED, actor="operator", reason="host decommissioned"
    )
    assert invalidated is not None
    assert invalidated.t_invalid is not None
    assert invalidated.is_active is False
    assert store.get_active("host:axiom", "os_version", OBSERVED) is None


def test_silent_invalidate_without_supersede_is_blocked(tmp_path: Path) -> None:
    # Setting t_invalid on an active row while leaving it un-superseded would retire a
    # fact without the supersede actor/reason provenance. The trigger blocks any UPDATE
    # that leaves the row active (NEW.t_superseded IS NULL) (BL-039).
    db = tmp_path / "store.db"
    store = SqliteStore(db)
    store.put_fact(_fact({"version": "24.04"}))
    store.close()

    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute("UPDATE facts SET t_invalid = '2026-06-07T01:00:00.000000Z'")
            conn.commit()
    finally:
        conn.close()


def test_tampering_a_superseded_row_is_blocked(tmp_path: Path) -> None:
    # The supersede transition is one-time: a second UPDATE (here rewriting the
    # supersede provenance) is refused (OLD.t_superseded IS NOT NULL) (BL-039).
    db = tmp_path / "store.db"
    store = SqliteStore(db)
    store.put_fact(_fact({"version": "24.04"}))
    store.supersede("host:axiom", "os_version", OBSERVED, actor="operator", reason="decom")
    store.close()

    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.Error):
            conn.execute("UPDATE facts SET superseded_reason = 'rewritten'")
            conn.commit()
    finally:
        conn.close()


def test_store_satisfies_protocol() -> None:
    store = SqliteStore()
    assert isinstance(store, StoreProtocol)
