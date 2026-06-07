"""Bitemporal behaviour: supersession chains and the four timestamps (ADR-0003)."""

from __future__ import annotations

from praxis.model import OBSERVED, Fact


def _os_fact(version: str) -> Fact:
    return Fact(
        subject="host:axiom",
        predicate="os_version",
        fact_type=OBSERVED,
        value={"version": version},
        t_valid="2026-06-07T00:00:00.000000Z",
        actor="collector",
    )


def test_history_is_ordered_supersession_chain() -> None:
    from praxis.store import SqliteStore

    store = SqliteStore()
    store.put_fact(_os_fact("22.04"))
    store.put_fact(_os_fact("24.04"))
    history = store.history("host:axiom", "os_version")
    assert [h.value["version"] for h in history] == ["22.04", "24.04"]
    # The older record is superseded (inactive); the newer is active.
    assert history[0].t_superseded is not None
    assert history[0].is_active is False
    assert history[1].t_superseded is None
    assert history[1].is_active is True


def test_recorded_time_assigned_by_store() -> None:
    from praxis.store import SqliteStore

    store = SqliteStore()
    raw = _os_fact("24.04")
    assert raw.t_recorded is None  # not yet recorded
    stored = store.put_fact(raw)
    assert stored.t_recorded is not None  # the store stamps recorded time


def test_supersede_sets_invalid_and_superseded() -> None:
    from praxis.store import SqliteStore

    store = SqliteStore()
    store.put_fact(_os_fact("24.04"))
    invalidated = store.supersede(
        "host:axiom", "os_version", OBSERVED, actor="operator", reason="rebuilt"
    )
    assert invalidated is not None
    assert invalidated.t_invalid is not None
    assert invalidated.t_superseded is not None
    # No active fact remains for the key.
    assert store.get_active("host:axiom", "os_version", OBSERVED) is None
    # But history retains it.
    assert len(store.history("host:axiom", "os_version")) == 1
