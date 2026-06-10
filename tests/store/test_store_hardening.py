"""Store hardening: owner-only file mode (BL-079) and seq uniqueness (BL-068)."""

from __future__ import annotations

import stat
from pathlib import Path

from praxis.model.facts import OBSERVED, Fact
from praxis.store import SqliteStore


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
