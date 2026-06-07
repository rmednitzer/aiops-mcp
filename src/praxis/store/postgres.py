"""Postgres + Apache AGE production store backend (ADR-0002; BL-006).

Behind the same ``StoreProtocol`` as the SQLite default. Bitemporality and
append-only are enforced at the storage layer by PL/pgSQL triggers and a partial
unique index, mirroring the SQLite backend exactly. Timestamps are stored as TEXT
(verbatim ISO 8601) and values as TEXT JSON, so a fact round-trips identically
across both backends.

``psycopg`` is imported lazily; the package imports and type-checks with the driver
absent. Install the ``postgres`` extra to use this backend. Native AGE graph
traversal is a tracked follow-up; edges use the same table model as SQLite.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from typing import Any

from praxis.clock import utc_now_iso
from praxis.model.facts import Capability, Edge, Fact

_APPEND_ONLY_FN = """
CREATE OR REPLACE FUNCTION praxis_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'append-only: deletion is blocked';
    END IF;
    IF OLD.t_superseded IS NOT NULL
       OR OLD.subject IS DISTINCT FROM NEW.subject
       OR OLD.value IS DISTINCT FROM NEW.value
       OR OLD.t_valid IS DISTINCT FROM NEW.t_valid
       OR OLD.t_recorded IS DISTINCT FROM NEW.t_recorded
       OR OLD.actor IS DISTINCT FROM NEW.actor
       OR OLD.seq IS DISTINCT FROM NEW.seq THEN
        RAISE EXCEPTION 'append-only: only a one-time supersede/invalidate is allowed';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS facts (
        fact_id TEXT PRIMARY KEY, subject TEXT NOT NULL, predicate TEXT NOT NULL,
        fact_type TEXT NOT NULL, value TEXT NOT NULL, t_valid TEXT NOT NULL,
        t_invalid TEXT, t_recorded TEXT NOT NULL, t_superseded TEXT,
        actor TEXT NOT NULL, reason TEXT, superseded_actor TEXT,
        superseded_reason TEXT, seq BIGINT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS facts_active_unique ON facts (subject, predicate, "
    "fact_type) WHERE t_invalid IS NULL AND t_superseded IS NULL",
    """
    CREATE TABLE IF NOT EXISTS edges (
        edge_id TEXT PRIMARY KEY, subject TEXT NOT NULL, relation TEXT NOT NULL,
        target TEXT NOT NULL, value TEXT NOT NULL, t_valid TEXT NOT NULL,
        t_invalid TEXT, t_recorded TEXT NOT NULL, t_superseded TEXT,
        actor TEXT NOT NULL, reason TEXT, seq BIGINT
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS edges_active_unique ON edges (subject, relation, "
    "target) WHERE t_invalid IS NULL AND t_superseded IS NULL",
    _APPEND_ONLY_FN,
    "DROP TRIGGER IF EXISTS facts_append_only ON facts",
    "CREATE TRIGGER facts_append_only BEFORE UPDATE OR DELETE ON facts "
    "FOR EACH ROW EXECUTE FUNCTION praxis_append_only()",
    "DROP TRIGGER IF EXISTS edges_append_only ON edges",
    "CREATE TRIGGER edges_append_only BEFORE UPDATE OR DELETE ON edges "
    "FOR EACH ROW EXECUTE FUNCTION praxis_append_only()",
]


def _loads_obj(raw: str) -> dict[str, object]:
    parsed = json.loads(raw)
    return parsed if isinstance(parsed, dict) else {}


class PostgresStore:
    """Production store backend. Implements ``StoreProtocol`` (ADR-0002)."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "PostgresStore requires the 'postgres' extra: pip install 'praxis[postgres]'"
            ) from exc
        self._conn: Any = psycopg.connect(dsn, autocommit=True, row_factory=dict_row)
        with self._conn.transaction():
            for statement in _SCHEMA:
                self._conn.execute(statement)

    def put_fact(self, fact: Fact) -> Fact:
        if not fact.actor:
            raise ValueError("put_fact requires a non-empty actor (write provenance)")
        now = utc_now_iso()
        fact_id = uuid.uuid4().hex
        with self._conn.transaction():
            seq = self._next_seq("facts")
            existing = self.get_active(fact.subject, fact.predicate, fact.fact_type)
            if existing is not None and existing.fact_id is not None:
                self._conn.execute(
                    "UPDATE facts SET t_superseded = %s WHERE fact_id = %s",
                    (now, existing.fact_id),
                )
            self._conn.execute(
                "INSERT INTO facts (fact_id, subject, predicate, fact_type, value, t_valid, "
                "t_invalid, t_recorded, t_superseded, actor, reason, seq) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
        with self._conn.transaction():
            self._conn.execute(
                "UPDATE facts SET t_invalid = %s, t_superseded = %s, superseded_actor = %s, "
                "superseded_reason = %s WHERE fact_id = %s AND t_superseded IS NULL",
                (now, now, actor, reason, existing.fact_id),
            )
        row = self._conn.execute(
            "SELECT * FROM facts WHERE fact_id = %s", (existing.fact_id,)
        ).fetchone()
        return _row_to_fact(row) if row is not None else None

    def get_active(self, subject: str, predicate: str, fact_type: str) -> Fact | None:
        row = self._conn.execute(
            "SELECT * FROM facts WHERE subject = %s AND predicate = %s AND fact_type = %s "
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
            clauses.append("subject = %s")
            params.append(subject)
        if fact_type is not None:
            clauses.append("fact_type = %s")
            params.append(fact_type)
        sql = f"SELECT * FROM facts WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_fact(row) for row in rows]

    def history(
        self, subject: str, predicate: str | None = None, fact_type: str | None = None
    ) -> list[Fact]:
        clauses = ["subject = %s"]
        params: list[object] = [subject]
        if predicate is not None:
            clauses.append("predicate = %s")
            params.append(predicate)
        if fact_type is not None:
            clauses.append("fact_type = %s")
            params.append(fact_type)
        sql = f"SELECT * FROM facts WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_fact(row) for row in rows]

    def put_edge(self, edge: Edge) -> Edge:
        if not edge.actor:
            raise ValueError("put_edge requires a non-empty actor")
        now = utc_now_iso()
        edge_id = uuid.uuid4().hex
        t_valid = edge.t_valid or now
        with self._conn.transaction():
            seq = self._next_seq("edges")
            existing = self._active_edge(edge.subject, edge.relation, edge.target)
            if existing is not None and existing.edge_id is not None:
                self._conn.execute(
                    "UPDATE edges SET t_superseded = %s WHERE edge_id = %s",
                    (now, existing.edge_id),
                )
            self._conn.execute(
                "INSERT INTO edges (edge_id, subject, relation, target, value, t_valid, "
                "t_invalid, t_recorded, t_superseded, actor, reason, seq) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
        clauses = ["subject = %s", "t_invalid IS NULL", "t_superseded IS NULL"]
        params: list[object] = [subject]
        if relation is not None:
            clauses.append("relation = %s")
            params.append(relation)
        sql = f"SELECT * FROM edges WHERE {' AND '.join(clauses)} ORDER BY seq"
        rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_edge(row) for row in rows]

    def _active_edge(self, subject: str, relation: str, target: str) -> Edge | None:
        row = self._conn.execute(
            "SELECT * FROM edges WHERE subject = %s AND relation = %s AND target = %s "
            "AND t_invalid IS NULL AND t_superseded IS NULL",
            (subject, relation, target),
        ).fetchone()
        return _row_to_edge(row) if row is not None else None

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
        return frozenset({Capability.GRAPH})

    def close(self) -> None:
        self._conn.close()


def _row_to_fact(row: Mapping[str, Any]) -> Fact:
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


def _row_to_edge(row: Mapping[str, Any]) -> Edge:
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
