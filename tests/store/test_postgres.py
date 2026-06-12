"""Postgres backend parity. Skips cleanly when psycopg or a live PG is absent (BL-006)."""

from __future__ import annotations

import os
import uuid

import pytest

psycopg = pytest.importorskip("psycopg")

from praxis.model import OBSERVED, Fact  # noqa: E402
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
