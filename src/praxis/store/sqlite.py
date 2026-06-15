"""SQLite store backend: the default, self-contained, no-daemon store (ADR-0002).

Bitemporality and append-only are enforced at the storage layer by triggers and a
partial unique index, not only in this Python code, so a direct write through
another connection cannot bypass the invariant (ADR-0003; SEC-10).

Vector search is provided by a pure-Python cosine fallback over a small embeddings
table, so ``Capability.VECTOR`` works with no extension installed. Native
``sqlite-vec`` acceleration is a tracked follow-up (BL-005 note in the README).
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path

from praxis.clock import utc_now_iso
from praxis.model.facts import Capability, Edge, Fact
from praxis.store.base import VersionConflict, synchronized

_SCHEMA = """
CREATE TABLE IF NOT EXISTS facts (
    fact_id           TEXT PRIMARY KEY,
    subject           TEXT NOT NULL,
    predicate         TEXT NOT NULL,
    fact_type         TEXT NOT NULL,
    value             TEXT NOT NULL,
    t_valid           TEXT NOT NULL,
    t_invalid         TEXT,
    t_recorded        TEXT NOT NULL,
    t_superseded      TEXT,
    actor             TEXT NOT NULL,
    reason            TEXT,
    superseded_actor  TEXT,
    superseded_reason TEXT,
    seq               INTEGER
);

-- At most one ACTIVE fact per (subject, predicate, fact_type) (ADR-0003).
CREATE UNIQUE INDEX IF NOT EXISTS facts_active_unique
    ON facts (subject, predicate, fact_type)
    WHERE t_invalid IS NULL AND t_superseded IS NULL;

CREATE INDEX IF NOT EXISTS facts_subject ON facts (subject);

-- seq is unique at the storage layer, so the inline MAX(seq)+1 computed in the
-- INSERT cannot silently collide across two store instances on one file: a race
-- fails loudly instead of corrupting the ordering (BL-068).
CREATE UNIQUE INDEX IF NOT EXISTS facts_seq_unique ON facts (seq);

-- Append-only: deletion is blocked unconditionally (SEC-10).
CREATE TRIGGER IF NOT EXISTS facts_no_delete
BEFORE DELETE ON facts
BEGIN
    SELECT RAISE(ABORT, 'facts are append-only: deletion is blocked');
END;

-- The only legal UPDATE is the one-time supersede/invalidate transition. Any
-- change to an immutable column, or any update of an already-superseded row, is
-- refused at the storage layer.
CREATE TRIGGER IF NOT EXISTS facts_append_only_update
BEFORE UPDATE ON facts
WHEN (
    OLD.fact_id    IS NOT NEW.fact_id    OR
    OLD.subject    IS NOT NEW.subject    OR
    OLD.predicate  IS NOT NEW.predicate  OR
    OLD.fact_type  IS NOT NEW.fact_type  OR
    OLD.value      IS NOT NEW.value      OR
    OLD.t_valid    IS NOT NEW.t_valid    OR
    OLD.t_recorded IS NOT NEW.t_recorded OR
    OLD.actor      IS NOT NEW.actor      OR
    OLD.reason     IS NOT NEW.reason     OR
    OLD.seq        IS NOT NEW.seq        OR
    OLD.t_superseded IS NOT NULL OR
    NEW.t_superseded IS NULL
)
BEGIN
    SELECT RAISE(ABORT,
        'facts are append-only: only a one-time supersede/invalidate is allowed');
END;

CREATE TABLE IF NOT EXISTS edges (
    edge_id      TEXT PRIMARY KEY,
    subject      TEXT NOT NULL,
    relation     TEXT NOT NULL,
    target       TEXT NOT NULL,
    value        TEXT NOT NULL,
    t_valid      TEXT NOT NULL,
    t_invalid    TEXT,
    t_recorded   TEXT NOT NULL,
    t_superseded TEXT,
    actor        TEXT NOT NULL,
    reason       TEXT,
    seq          INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS edges_active_unique
    ON edges (subject, relation, target)
    WHERE t_invalid IS NULL AND t_superseded IS NULL;

CREATE INDEX IF NOT EXISTS edges_subject ON edges (subject);

CREATE UNIQUE INDEX IF NOT EXISTS edges_seq_unique ON edges (seq);

CREATE TRIGGER IF NOT EXISTS edges_no_delete
BEFORE DELETE ON edges
BEGIN
    SELECT RAISE(ABORT, 'edges are append-only: deletion is blocked');
END;

CREATE TRIGGER IF NOT EXISTS edges_append_only_update
BEFORE UPDATE ON edges
WHEN (
    OLD.edge_id    IS NOT NEW.edge_id    OR
    OLD.subject    IS NOT NEW.subject    OR
    OLD.relation   IS NOT NEW.relation   OR
    OLD.target     IS NOT NEW.target     OR
    OLD.value      IS NOT NEW.value      OR
    OLD.t_valid    IS NOT NEW.t_valid    OR
    OLD.t_recorded IS NOT NEW.t_recorded OR
    OLD.actor      IS NOT NEW.actor      OR
    OLD.reason     IS NOT NEW.reason     OR
    OLD.seq        IS NOT NEW.seq        OR
    OLD.t_superseded IS NOT NULL OR
    NEW.t_superseded IS NULL
)
BEGIN
    SELECT RAISE(ABORT,
        'edges are append-only: only a one-time supersede/invalidate is allowed');
END;

CREATE TABLE IF NOT EXISTS embeddings (
    fact_id TEXT PRIMARY KEY,
    vector  TEXT NOT NULL
);
"""


def _loads_obj(raw: str) -> dict[str, object]:
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


def _precreate_owner_only(path: str) -> None:
    """Create (or re-permission) the store file ``0o600`` before SQLite opens it.

    Restricted facts must not be group or world readable on a shared host. SQLite
    creates the WAL/SHM sidecars with the database file's permissions, so fixing
    the database file covers them too (BL-079; mirrors the audit sink, BL-064).
    A path SQLite cannot use anyway (a directory, an exotic DSN) is left for
    ``sqlite3.connect`` to refuse with its own error.
    """
    try:
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        os.chmod(path, 0o600)
    except OSError:
        return


class SqliteStore:
    """The default store backend. Implements ``StoreProtocol`` and ``VectorStore``."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            _precreate_owner_only(self.path)
        # check_same_thread=False lets the threaded HTTP transport (ADR-0042) use the one
        # connection from any handler thread; the @synchronized RLock serialises every
        # access, which is the documented-safe single-connection pattern (BL-110).
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Wait on a held write lock rather than failing fast, so a compare-and-set
        # (BEGIN IMMEDIATE) on one store instance serialises against a second
        # instance on the same file instead of raising "database is locked"
        # (BL-027; the multi-instance case BL-068 anticipated).
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------ facts
    @synchronized
    def put_fact(self, fact: Fact) -> Fact:
        if not fact.actor:
            raise ValueError("put_fact requires a non-empty actor (write provenance)")
        now = utc_now_iso()
        fact_id = uuid.uuid4().hex
        with self._conn:
            existing = self.get_active(fact.subject, fact.predicate, fact.fact_type)
            self._write_superseding(existing, fact, fact_id=fact_id, now=now)
        stored = self.get_active(fact.subject, fact.predicate, fact.fact_type)
        if stored is None:  # pragma: no cover - storage invariant
            raise RuntimeError("invariant violated: just-inserted fact is not active")
        return stored

    @synchronized
    def put_fact_if(self, fact: Fact, *, expected_version: str | None) -> Fact:
        """Version-gated supersede (``VersionedStore``; BL-027, ADR-0021).

        Reads the active fact under an IMMEDIATE write lock, compares its
        ``content_hash`` to ``expected_version`` (or asserts absence when None), and
        only then supersedes-and-inserts. A mismatch raises ``VersionConflict`` and
        writes nothing, so an operator approval bound to the fact they read cannot be
        applied to a different value that landed in between (SEC-6, invariant 4).
        """
        if not fact.actor:
            raise ValueError("put_fact_if requires a non-empty actor (write provenance)")
        now = utc_now_iso()
        fact_id = uuid.uuid4().hex
        with self._immediate():
            existing = self.get_active(fact.subject, fact.predicate, fact.fact_type)
            current = existing.content_hash() if existing is not None else None
            if current != expected_version:
                raise VersionConflict(
                    f"compare-and-set rejected for "
                    f"{fact.subject}/{fact.predicate}/{fact.fact_type}: "
                    f"expected version {expected_version!r}, active is {current!r}"
                )
            self._write_superseding(existing, fact, fact_id=fact_id, now=now)
        stored = self.get_active(fact.subject, fact.predicate, fact.fact_type)
        if stored is None:  # pragma: no cover - storage invariant
            raise RuntimeError("invariant violated: just-inserted fact is not active")
        return stored

    @contextmanager
    def _immediate(self) -> Iterator[None]:
        """An IMMEDIATE write transaction: take the write lock up front so a
        compare-and-set read-then-write serialises against a concurrent writer rather
        than racing to a loud IntegrityError on the partial unique index (BL-027)."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.rollback()
            raise
        else:
            self._conn.commit()

    def _write_superseding(
        self, existing: Fact | None, fact: Fact, *, fact_id: str, now: str
    ) -> None:
        """Supersede the prior active row (if any) BEFORE inserting the new one, so
        the partial unique index never sees two active rows for the key. seq is
        computed inside the INSERT itself, so the read and the write are one atomic
        statement; the unique index on seq turns any residual cross-instance race
        into a loud IntegrityError (BL-068). Shared by ``put_fact`` and
        ``put_fact_if`` so the two write paths cannot drift."""
        if existing is not None and existing.fact_id is not None:
            self._conn.execute(
                "UPDATE facts SET t_superseded = ? WHERE fact_id = ?",
                (now, existing.fact_id),
            )
        self._conn.execute(
            "INSERT INTO facts (fact_id, subject, predicate, fact_type, value, "
            "t_valid, t_invalid, t_recorded, t_superseded, actor, reason, seq) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
            "(SELECT COALESCE(MAX(seq), -1) + 1 FROM facts))",
            (
                fact_id,
                fact.subject,
                fact.predicate,
                fact.fact_type,
                json.dumps(fact.value, sort_keys=True),
                fact.t_valid,
                fact.t_invalid,
                now,
                None,
                fact.actor,
                fact.reason,
            ),
        )

    @synchronized
    def supersede(
        self, subject: str, predicate: str, fact_type: str, *, actor: str, reason: str
    ) -> Fact | None:
        if not actor or not reason:
            raise ValueError("supersede requires a non-empty actor and reason (SEC-10)")
        existing = self.get_active(subject, predicate, fact_type)
        if existing is None or existing.fact_id is None:
            return None
        now = utc_now_iso()
        with self._conn:
            # The supersession actor/reason are recorded in dedicated columns; the
            # original recording reason stays immutable (append-only).
            cur = self._conn.execute(
                "UPDATE facts SET t_invalid = ?, t_superseded = ?, superseded_actor = ?, "
                "superseded_reason = ? WHERE fact_id = ? AND t_superseded IS NULL",
                (now, now, actor, reason, existing.fact_id),
            )
            # F-007: a concurrent supersede may have won between get_active above and this
            # UPDATE, so the WHERE clause matched 0 rows. Report the lost race as None
            # rather than returning a row another actor superseded with their own
            # actor/reason, which would falsely claim this caller's supersede won
            # (provenance fidelity, SEC-10).
            if cur.rowcount != 1:
                return None
        row = self._conn.execute(
            "SELECT * FROM facts WHERE fact_id = ?", (existing.fact_id,)
        ).fetchone()
        return _row_to_fact(row) if row is not None else None

    @synchronized
    def get_active(self, subject: str, predicate: str, fact_type: str) -> Fact | None:
        row = self._conn.execute(
            "SELECT * FROM facts WHERE subject = ? AND predicate = ? AND fact_type = ? "
            "AND t_invalid IS NULL AND t_superseded IS NULL",
            (subject, predicate, fact_type),
        ).fetchone()
        return _row_to_fact(row) if row is not None else None

    @synchronized
    def list_active(
        self, *, subject: str | None = None, fact_type: str | None = None
    ) -> list[Fact]:
        clauses = ["t_invalid IS NULL", "t_superseded IS NULL"]
        params: list[object] = []
        if subject is not None:
            clauses.append("subject = ?")
            params.append(subject)
        if fact_type is not None:
            clauses.append("fact_type = ?")
            params.append(fact_type)
        sql = f"SELECT * FROM facts WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_fact(row) for row in rows]

    @synchronized
    def history(
        self, subject: str, predicate: str | None = None, fact_type: str | None = None
    ) -> list[Fact]:
        clauses = ["subject = ?"]
        params: list[object] = [subject]
        if predicate is not None:
            clauses.append("predicate = ?")
            params.append(predicate)
        if fact_type is not None:
            clauses.append("fact_type = ?")
            params.append(fact_type)
        sql = f"SELECT * FROM facts WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_fact(row) for row in rows]

    # ------------------------------------------------------------------ edges
    @synchronized
    def put_edge(self, edge: Edge) -> Edge:
        if not edge.actor:
            raise ValueError("put_edge requires a non-empty actor")
        now = utc_now_iso()
        edge_id = uuid.uuid4().hex
        t_valid = edge.t_valid or now
        with self._conn:
            existing = self._active_edge(edge.subject, edge.relation, edge.target)
            if existing is not None and existing.edge_id is not None:
                self._conn.execute(
                    "UPDATE edges SET t_superseded = ? WHERE edge_id = ?",
                    (now, existing.edge_id),
                )
            self._conn.execute(
                "INSERT INTO edges (edge_id, subject, relation, target, value, "
                "t_valid, t_invalid, t_recorded, t_superseded, actor, reason, seq) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "(SELECT COALESCE(MAX(seq), -1) + 1 FROM edges))",
                (
                    edge_id,
                    edge.subject,
                    edge.relation,
                    edge.target,
                    json.dumps(edge.value, sort_keys=True),
                    t_valid,
                    edge.t_invalid,
                    now,
                    None,
                    edge.actor,
                    edge.reason,
                ),
            )
        stored = self._active_edge(edge.subject, edge.relation, edge.target)
        if stored is None:  # pragma: no cover - storage invariant
            raise RuntimeError("invariant violated: just-inserted edge is not active")
        return stored

    @synchronized
    def edges_from(self, subject: str, relation: str | None = None) -> list[Edge]:
        clauses = ["subject = ?", "t_invalid IS NULL", "t_superseded IS NULL"]
        params: list[object] = [subject]
        if relation is not None:
            clauses.append("relation = ?")
            params.append(relation)
        sql = f"SELECT * FROM edges WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_edge(row) for row in rows]

    def _active_edge(self, subject: str, relation: str, target: str) -> Edge | None:
        row = self._conn.execute(
            "SELECT * FROM edges WHERE subject = ? AND relation = ? AND target = ? "
            "AND t_invalid IS NULL AND t_superseded IS NULL",
            (subject, relation, target),
        ).fetchone()
        return _row_to_edge(row) if row is not None else None

    # ------------------------------------------------------------- embeddings
    @synchronized
    def upsert_embedding(self, fact_id: str, vector: Sequence[float]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO embeddings (fact_id, vector) VALUES (?, ?) "
                "ON CONFLICT(fact_id) DO UPDATE SET vector = excluded.vector",
                (fact_id, json.dumps(list(vector))),
            )

    @synchronized
    def similar(self, vector: Sequence[float], *, k: int = 10) -> list[tuple[str, float]]:
        query = [float(x) for x in vector]
        if not _all_finite(query):
            raise ValueError("query vector must be finite (no NaN/inf)")
        rows = self._conn.execute("SELECT fact_id, vector FROM embeddings").fetchall()
        scored: list[tuple[str, float]] = []
        for row in rows:
            stored = _finite_vector(json.loads(row["vector"]))
            if stored is None:
                # A stored vector with a non-finite or non-numeric component is
                # skipped rather than allowed to poison the ranking with a NaN
                # score (BL-054). Untrusted/corrupted embeddings cannot rank.
                continue
            scored.append((str(row["fact_id"]), _cosine(query, stored)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    # --------------------------------------------------------------- plumbing
    def capabilities(self) -> frozenset[Capability]:
        return frozenset({Capability.VECTOR, Capability.COMPARE_AND_SET})

    @synchronized
    def close(self) -> None:
        self._conn.close()


def _row_to_fact(row: sqlite3.Row) -> Fact:
    return Fact(
        subject=str(row["subject"]),
        predicate=str(row["predicate"]),
        fact_type=str(row["fact_type"]),
        value=_loads_obj(str(row["value"])),
        t_valid=str(row["t_valid"]),
        actor=str(row["actor"]),
        reason=row["reason"],
        t_invalid=row["t_invalid"],
        t_recorded=str(row["t_recorded"]),
        t_superseded=row["t_superseded"],
        fact_id=str(row["fact_id"]),
    )


def _row_to_edge(row: sqlite3.Row) -> Edge:
    return Edge(
        subject=str(row["subject"]),
        relation=str(row["relation"]),
        target=str(row["target"]),
        value=_loads_obj(str(row["value"])),
        t_valid=str(row["t_valid"]),
        actor=str(row["actor"]),
        reason=row["reason"],
        t_invalid=row["t_invalid"],
        t_recorded=str(row["t_recorded"]),
        t_superseded=row["t_superseded"],
        edge_id=str(row["edge_id"]),
    )


def _all_finite(vector: Sequence[float]) -> bool:
    return all(math.isfinite(x) for x in vector)


def _finite_vector(raw: object) -> list[float] | None:
    """Coerce a stored vector to a list of finite floats, or None if it cannot be.

    A non-list, a non-numeric component, or a NaN/inf component yields None so the
    caller can skip a corrupted embedding rather than rank on a poisoned score.
    """
    if not isinstance(raw, list):
        return None
    out: list[float] = []
    for item in raw:
        try:
            value = float(item)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(value):
            return None
        out.append(value)
    return out


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    result = dot / (norm_a * norm_b)
    return result if math.isfinite(result) else 0.0
