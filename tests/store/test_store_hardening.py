"""Store hardening: owner-only file mode (BL-079), seq uniqueness (BL-068), and the
compare-and-set lost-update guard under real concurrency (BL-027)."""

from __future__ import annotations

import stat
import threading
from pathlib import Path

import pytest

from praxis.model.facts import OBSERVED, Fact
from praxis.store import SqliteStore
from praxis.store.base import VersionConflict


def _fact(predicate: str, value: str) -> Fact:
    return Fact(
        subject="host:axiom",
        predicate=predicate,
        fact_type=OBSERVED,
        value={"v": value},
        t_valid="2026-06-10T00:00:00.000000Z",
        actor="test",
    )


def test_store_file_is_owner_only(tmp_path: Path) -> None:
    # BL-079: restricted facts must not be group/world readable on a shared host.
    db = tmp_path / "praxis.db"
    store = SqliteStore(db)
    store.put_fact(_fact("os", "ubuntu"))
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    store.close()


def test_pre_existing_store_file_is_repermissioned(tmp_path: Path) -> None:
    db = tmp_path / "praxis.db"
    db.touch(mode=0o644)
    db.chmod(0o644)
    store = SqliteStore(db)
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    store.close()


def test_store_is_thread_safe_for_concurrent_writes(tmp_path: Path) -> None:
    # BL-110: the threaded HTTP transport shares one store across handler threads.
    # check_same_thread=False plus the @synchronized RLock make concurrent use safe:
    # every write from 10 threads lands, with no cross-thread error and no seq collision.
    store = SqliteStore(tmp_path / "praxis.db")
    barrier = threading.Barrier(10)

    def writer(worker: int) -> None:
        barrier.wait()
        for i in range(20):
            store.put_fact(
                Fact(
                    subject=f"host:h{worker}",
                    predicate=f"p{i}",
                    fact_type=OBSERVED,
                    value={"i": i},
                    t_valid="2026-06-10T00:00:00.000000Z",
                    actor="test",
                )
            )

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(store.list_active()) == 10 * 20  # all distinct-key writes present
    seqs = [row["seq"] for row in store._conn.execute("SELECT seq FROM facts").fetchall()]
    assert len(seqs) == len(set(seqs)) == 200  # unique seqs: no lost or corrupted write
    store.close()


def test_seq_is_unique_across_two_store_instances(tmp_path: Path) -> None:
    # BL-068: the seq is computed inside the INSERT and is unique at the storage
    # layer, so two store instances on one file cannot interleave duplicate seqs.
    db = tmp_path / "praxis.db"
    a = SqliteStore(db)
    b = SqliteStore(db)
    a.put_fact(_fact("p1", "from-a"))
    b.put_fact(_fact("p2", "from-b"))
    a.put_fact(_fact("p3", "from-a-again"))
    rows = a._conn.execute("SELECT seq FROM facts ORDER BY seq").fetchall()
    seqs = [row["seq"] for row in rows]
    assert seqs == sorted(set(seqs)), f"duplicate or unordered seqs: {seqs}"
    assert len(seqs) == 3
    a.close()
    b.close()


def test_compare_and_set_serialises_concurrent_writers(tmp_path: Path) -> None:
    # BL-027: two store instances on one file race to supersede the SAME active fact
    # from the SAME read. The IMMEDIATE write lock plus busy_timeout serialises them,
    # so exactly one wins and the other sees VersionConflict; the lost update never
    # lands. Invariant 4 (one active fact, no silent overwrite) holds under contention.
    db = tmp_path / "praxis.db"
    setup = SqliteStore(db)
    base = setup.put_fact(_fact("kernel", "6.17"))
    version = base.content_hash()
    setup.close()

    barrier = threading.Barrier(2)
    results: dict[str, str] = {}
    errors: dict[str, BaseException] = {}

    def writer(name: str, new_value: str) -> None:
        store = SqliteStore(db)
        try:
            barrier.wait(timeout=5)
            store.put_fact_if(_fact("kernel", new_value), expected_version=version)
            results[name] = new_value
        except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
            errors[name] = exc
        finally:
            store.close()

    threads = [
        threading.Thread(target=writer, args=("t1", "6.18"), daemon=True),
        threading.Thread(target=writer, args=("t2", "6.19"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        # A hung writer (deadlock past the timeout) must fail the test loudly, not
        # leave a runaway non-daemon thread keeping the process alive.
        assert not thread.is_alive(), "writer thread did not finish within 10 s"

    # Exactly one writer committed; the other was refused as a stale CAS.
    assert len(results) == 1, f"expected one winner, got {results} / {errors}"
    assert len(errors) == 1
    assert isinstance(next(iter(errors.values())), VersionConflict)

    verify = SqliteStore(db)
    active = verify.get_active("host:axiom", "kernel", OBSERVED)
    assert active is not None
    assert active.value == {"v": next(iter(results.values()))}  # the winner's value
    # Exactly the base row plus the one winning write: the loser wrote nothing.
    assert len(verify.history("host:axiom", "kernel")) == 2
    verify.close()


def test_put_fact_if_writes_nothing_on_conflict(tmp_path: Path) -> None:
    # A rejected CAS must leave the seq sequence and the row count untouched: the
    # rollback is complete, not a half-written row that later breaks verification.
    db = tmp_path / "praxis.db"
    store = SqliteStore(db)
    store.put_fact(_fact("os", "ubuntu"))
    with pytest.raises(VersionConflict):
        store.put_fact_if(_fact("os", "debian"), expected_version="0" * 64)
    rows = store.history("host:axiom", "os")
    assert len(rows) == 1
    assert rows[0].value == {"v": "ubuntu"}
    store.close()


def test_supersede_reports_a_lost_race_as_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # F-007: if a concurrent supersede wins between get_active and the guarded UPDATE,
    # the UPDATE matches 0 rows. supersede must return None (this caller lost) rather
    # than falsely returning a row another actor superseded with their own actor/reason.
    db = tmp_path / "praxis.db"
    store = SqliteStore(db)
    store.put_fact(_fact("kernel", "6.17"))
    won = store.supersede("host:axiom", "kernel", OBSERVED, actor="a", reason="r1")
    assert won is not None  # the winner gets the superseded row back
    # The losing caller's read is stale: get_active hands back the now-superseded row,
    # so the guarded UPDATE (WHERE t_superseded IS NULL) matches nothing.
    monkeypatch.setattr(store, "get_active", lambda *a, **k: won)
    lost = store.supersede("host:axiom", "kernel", OBSERVED, actor="b", reason="r2")
    assert lost is None
    store.close()
