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
import sqlite3
import uuid
from collections.abc import Sequence
from pathlib import Path

from praxis.clock import utc_now_iso
from praxis.model.facts import Capability, Edge, Fact

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


class SqliteStore:
    """The default store backend. Implements ``StoreProtocol`` and ``VectorStore``."""

    def __init__(self, path: Path | str = ":memory:") -> None:
        self.path = str(path)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------ facts
    def put_fact(self, fact: Fact) -> Fact:
        if not fact.actor:
            raise ValueError("put_fact requires a non-empty actor (write provenance)")
        now = utc_now_iso()
        fact_id = uuid.uuid4().hex
        with self._conn:
            seq = self._next_seq("facts")
            existing = self.get_active(fact.subject, fact.predicate, fact.fact_type)
            if existing is not None and existing.fact_id is not None:
                # Supersede the prior active row BEFORE inserting the new one so the
                # partial unique index never sees two active rows for the key.
                self._conn.execute(
                    "UPDATE facts SET t_superseded = ? WHERE fact_id = ?",
                    (now, existing.fact_id),
                )
            self._conn.execute(
                "INSERT INTO facts (fact_id, subject, predicate, fact_type, value, "
                "t_valid, t_invalid, t_recorded, t_superseded, actor, reason, seq) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    seq,
                ),
            )
        stored = self.get_active(fact.subject, fact.predicate, fact.fact_type)
        if stored is None:  # pragma: no cover - storage invariant
            raise RuntimeError("invariant violated: just-inserted fact is not active")
        return stored

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
            self._conn.execute(
                "UPDATE facts SET t_invalid = ?, t_superseded = ?, superseded_actor = ?, "
                "superseded_reason = ? WHERE fact_id = ? AND t_superseded IS NULL",
                (now, now, actor, reason, existing.fact_id),
            )
        row = self._conn.execute(
            "SELECT * FROM facts WHERE fact_id = ?", (existing.fact_id,)
        ).fetchone()
        return _row_to_fact(row) if row is not None else None

    def get_active(self, subject: str, predicate: str, fact_type: str) -> Fact | None:
        row = self._conn.execute(
            "SELECT * FROM facts WHERE subject = ? AND predicate = ? AND fact_type = ? "
            "AND t_invalid IS NULL AND t_superseded IS NULL",
            (subject, predicate, fact_type),
        ).fetchone()
        return _row_to_fact(row) if row is not None else None

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
    def put_edge(self, edge: Edge) -> Edge:
        if not edge.actor:
            raise ValueError("put_edge requires a non-empty actor")
        now = utc_now_iso()
        edge_id = uuid.uuid4().hex
        t_valid = edge.t_valid or now
        with self._conn:
            seq = self._next_seq("edges")
            existing = self._active_edge(edge.subject, edge.relation, edge.target)
            if existing is not None and existing.edge_id is not None:
                self._conn.execute(
                    "UPDATE edges SET t_superseded = ? WHERE edge_id = ?",
                    (now, existing.edge_id),
                )
            self._conn.execute(
                "INSERT INTO edges (edge_id, subject, relation, target, value, "
                "t_valid, t_invalid, t_recorded, t_superseded, actor, reason, seq) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                    seq,
                ),
            )
        stored = self._active_edge(edge.subject, edge.relation, edge.target)
        if stored is None:  # pragma: no cover - storage invariant
            raise RuntimeError("invariant violated: just-inserted edge is not active")
        return stored

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
    def upsert_embedding(self, fact_id: str, vector: Sequence[float]) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO embeddings (fact_id, vector) VALUES (?, ?) "
                "ON CONFLICT(fact_id) DO UPDATE SET vector = excluded.vector",
                (fact_id, json.dumps(list(vector))),
            )

    def similar(self, vector: Sequence[float], *, k: int = 10) -> list[tuple[str, float]]:
        query = list(vector)
        rows = self._conn.execute("SELECT fact_id, vector FROM embeddings").fetchall()
        scored: list[tuple[str, float]] = []
        for row in rows:
            stored = [float(x) for x in json.loads(row["vector"])]
            scored.append((str(row["fact_id"]), _cosine(query, stored)))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:k]

    # --------------------------------------------------------------- plumbing
    def _next_seq(self, table: str) -> int:
        # Table is never interpolated from caller input: only these two literals.
        if table == "facts":
            sql = "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM facts"
        elif table == "edges":
            sql = "SELECT COALESCE(MAX(seq), -1) + 1 AS n FROM edges"
        else:
            raise ValueError(f"unknown table {table!r}")
        row = self._conn.execute(sql).fetchone()
        return int(row["n"])

    def capabilities(self) -> frozenset[Capability]:
        return frozenset({Capability.VECTOR})

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


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)
