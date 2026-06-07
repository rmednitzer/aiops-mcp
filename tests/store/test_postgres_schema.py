"""Static parity guard for the Postgres append-only triggers (BL-038).

Runs without psycopg or a live database: it inspects the SQL the backend would
install. The reproduced finding was a single shared trigger function that left
each table's identity columns unguarded; this asserts per-table functions that
guard every identity and provenance column plus the one-time supersede transition,
matching the SQLite backend's storage-layer guarantees (invariant 4).
"""

from __future__ import annotations

from praxis.store.postgres import (
    _EDGES_APPEND_ONLY_FN,
    _FACTS_APPEND_ONLY_FN,
    _SCHEMA,
)

_FACT_GUARDED = (
    "fact_id",
    "subject",
    "predicate",
    "fact_type",
    "value",
    "t_valid",
    "t_recorded",
    "actor",
    "reason",
    "seq",
)
_EDGE_GUARDED = (
    "edge_id",
    "subject",
    "relation",
    "target",
    "value",
    "t_valid",
    "t_recorded",
    "actor",
    "reason",
    "seq",
)


def test_facts_function_guards_every_identity_column() -> None:
    for col in _FACT_GUARDED:
        assert f"NEW.{col}" in _FACTS_APPEND_ONLY_FN, col
    assert "OLD.t_superseded IS NOT NULL" in _FACTS_APPEND_ONLY_FN
    assert "NEW.t_superseded IS NULL" in _FACTS_APPEND_ONLY_FN
    assert "DELETE" in _FACTS_APPEND_ONLY_FN


def test_edges_function_guards_every_identity_column() -> None:
    for col in _EDGE_GUARDED:
        assert f"NEW.{col}" in _EDGES_APPEND_ONLY_FN, col
    assert "OLD.t_superseded IS NOT NULL" in _EDGES_APPEND_ONLY_FN
    assert "NEW.t_superseded IS NULL" in _EDGES_APPEND_ONLY_FN
    assert "DELETE" in _EDGES_APPEND_ONLY_FN


def test_schema_installs_distinct_per_table_functions() -> None:
    joined = "\n".join(_SCHEMA)
    assert "EXECUTE FUNCTION praxis_facts_append_only()" in joined
    assert "EXECUTE FUNCTION praxis_edges_append_only()" in joined
