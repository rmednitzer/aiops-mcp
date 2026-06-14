"""Postgres backend parity. Skips cleanly when psycopg or a live PG is absent (BL-006)."""

from __future__ import annotations

import os
import threading
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from praxis.model import OBSERVED, Fact  # noqa: E402
from praxis.store.base import VersionConflict  # noqa: E402
from praxis.store.postgres import PostgresStore  # noqa: E402

PG_DSN = os.environ.get("PRAXIS_TEST_PG_DSN")
pytestmark = pytest.mark.skipif(
    not PG_DSN, reason="set PRAXIS_TEST_PG_DSN to run Postgres backend tests"
)


def _os_fact() -> Fact:
    return Fact(
        subject="host:pgtest",
        predicate="os_version",
        fact_type=OBSERVED,
        value={"version": "24.04"},
        t_valid="2026-06-07T00:00:00.000000Z",
        actor="collector",
    )


def _fact(subject: str, predicate: str, value: str) -> Fact:
    return Fact(
        subject=subject,
        predicate=predicate,
        fact_type=OBSERVED,
        value={"v": value},
        t_valid="2026-06-12T00:00:00.000000Z",
        actor="test",
    )


def _store() -> PostgresStore:
    assert PG_DSN is not None
    return PostgresStore(PG_DSN)


def test_postgres_roundtrip() -> None:
    store = _store()
    stored = store.put_fact(_os_fact())
    assert stored.fact_id is not None
    got = store.get_active("host:pgtest", "os_version", OBSERVED)
    assert got is not None
    assert got.value["version"] == "24.04"
    store.close()


def test_seq_is_unique_across_two_store_instances() -> None:
    # BL-091 (BL-068 parity): seq is computed inside the INSERT under a unique
    # index, so two store instances on one database cannot interleave duplicate
    # seqs; the table-wide sequence stays strictly increasing.
    subject = f"host:race-{uuid.uuid4().hex[:8]}"
    a, b = _store(), _store()
    a.put_fact(_fact(subject, "p1", "x"))
    b.put_fact(_fact(subject, "p2", "y"))
    a.put_fact(_fact(subject, "p3", "z"))
    rows = a._conn.execute(
        "SELECT seq FROM facts WHERE subject = %s ORDER BY seq", (subject,)
    ).fetchall()
    seqs = [row["seq"] for row in rows]
    assert seqs == sorted(set(seqs)), f"duplicate or unordered seqs: {seqs}"
    assert len(seqs) == 3
    a.close()
    b.close()


def test_duplicate_seq_fails_loudly() -> None:
    # BL-091: the unique index turns a raced duplicate into a UniqueViolation
    # instead of silently corrupting the ordering.
    store = _store()
    store.put_fact(_fact(f"host:dup-{uuid.uuid4().hex[:8]}", "p", "v"))
    row = store._conn.execute("SELECT MAX(seq) AS n FROM facts").fetchone()
    taken = int(row["n"])
    with pytest.raises(psycopg.errors.UniqueViolation):
        store._conn.execute(
            "INSERT INTO facts (fact_id, subject, predicate, fact_type, value, "
            "t_valid, t_recorded, actor, seq) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                uuid.uuid4().hex,
                "host:dup",
                "p2",
                OBSERVED,
                "{}",
                "2026-06-12T00:00:00.000000Z",
                "2026-06-12T00:00:00.000000Z",
                "test",
                taken,
            ),
        )
    store.close()


def test_truncate_is_blocked() -> None:
    # BL-028: TRUNCATE bypasses row-level triggers; the statement-level trigger
    # must refuse it on both tables.
    store = _store()
    store.put_fact(_fact(f"host:trunc-{uuid.uuid4().hex[:8]}", "p", "v"))
    for table in ("facts", "edges"):
        with pytest.raises(psycopg.errors.RaiseException, match="TRUNCATE is blocked"):
            store._conn.execute(f"TRUNCATE {table}")  # noqa: S608 - literal table, test
    store.close()


def test_delete_is_blocked() -> None:
    # Invariant 4 live: the per-row trigger refuses deletion (BL-038).
    store = _store()
    subject = f"host:del-{uuid.uuid4().hex[:8]}"
    store.put_fact(_fact(subject, "p", "v"))
    with pytest.raises(psycopg.errors.RaiseException, match="deletion is blocked"):
        store._conn.execute("DELETE FROM facts WHERE subject = %s", (subject,))
    store.close()


def test_concurrent_create_if_absent_yields_one_winner_and_versionconflict() -> None:
    # BL-103 (BL-027, ADR-0021): the create-if-absent CAS path cannot `SELECT ... FOR
    # UPDATE`-lock a fact that does not exist yet, so two concurrent writers can both
    # pass the version compare-check. The partial unique index `facts_active_unique`
    # then lets exactly one INSERT win; the other trips an IntegrityError that
    # PostgresStore translates to VersionConflict (put_fact_if), so the create path
    # honours the same compare-and-set contract as the supersede path and the SQLite
    # backend's `BEGIN IMMEDIATE` serialization. This is the live-database race that
    # could not be exercised without a real Postgres (the translation is verified by
    # reasoning in the unit suite; here it is verified under genuine contention).
    #
    # Two writers, the same key, both expected_version=None: exactly one wins, the
    # other raises VersionConflict and writes nothing. A barrier releases the two
    # threads together so their transactions actually contend.
    subject = f"host:cas-race-{uuid.uuid4().hex[:8]}"
    barrier = threading.Barrier(2)
    results: dict[str, Fact] = {}
    errors: dict[str, BaseException] = {}

    def writer(name: str, version: str) -> None:
        # Each thread owns its own store/connection (psycopg connections are not
        # shared across threads); the connection is created and used in this thread.
        store = _store()
        try:
            barrier.wait(timeout=15)
            results[name] = store.put_fact_if(_fact(subject, "os", version), expected_version=None)
        except Exception as exc:  # captured so the assertions below can report it
            errors[name] = exc
        finally:
            store.close()

    threads = [
        threading.Thread(target=writer, args=("a", "ubuntu-24.04")),
        threading.Thread(target=writer, args=("b", "ubuntu-26.04")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)

    assert all(not thread.is_alive() for thread in threads), "a writer thread hung"
    assert len(results) == 1, f"expected one winner: results={results} errors={errors}"
    assert len(errors) == 1, f"expected one loser: results={results} errors={errors}"
    (loser_exc,) = errors.values()
    assert isinstance(loser_exc, VersionConflict), (
        f"the loser must raise VersionConflict, not a raw error: {loser_exc!r}"
    )

    # The loser's transaction rolled back: exactly the winner's single active row
    # survives, no phantom write (invariant 4).
    checker = _store()
    try:
        active = checker.get_active(subject, "os", OBSERVED)
        assert active is not None
        (winner,) = results.values()
        assert active.value == winner.value
        assert len(checker.history(subject, "os")) == 1
    finally:
        checker.close()
