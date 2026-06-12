"""Static parity guard for the Postgres append-only triggers (BL-038).

Runs without psycopg or a live database: it inspects the SQL the backend would
install. The reproduced finding was a single shared trigger function that left
each table's identity columns unguarded; this asserts per-table functions that
guard every identity and provenance column plus the one-time supersede transition,
matching the SQLite backend's storage-layer guarantees (invariant 4). The live
behavior of the same statements is covered in ``test_postgres.py`` when a
``PRAXIS_TEST_PG_DSN`` database is available.
"""

from __future__ import annotations

from praxis.store.postgres import (
    _EDGES_APPEND_ONLY_FN,
    _EDGES_INSERT,
    _FACTS_APPEND_ONLY_FN,
    _FACTS_INSERT,
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


def test_seq_is_unique_at_the_storage_layer() -> None:
    # BL-091 (BL-068 parity): without these indexes a cross-instance MAX(seq)+1
    # race silently corrupts fact ordering instead of failing loudly.
    joined = "\n".join(_SCHEMA)
    assert "CREATE UNIQUE INDEX IF NOT EXISTS facts_seq_unique ON facts (seq)" in joined
    assert "CREATE UNIQUE INDEX IF NOT EXISTS edges_seq_unique ON edges (seq)" in joined


def test_seq_is_computed_inside_the_insert() -> None:
    # BL-091: the read and the write must be one statement, not a separate
    # SELECT MAX(seq) racing ahead of the INSERT.
    assert "(SELECT COALESCE(MAX(seq), -1) + 1 FROM facts)" in _FACTS_INSERT
    assert "(SELECT COALESCE(MAX(seq), -1) + 1 FROM edges)" in _EDGES_INSERT


def test_truncate_is_blocked_by_statement_trigger() -> None:
    # BL-028: row-level triggers do not fire for TRUNCATE; the statement-level
    # trigger is the enforcing control (the PUBLIC revoke does not bind the owner).
    joined = "\n".join(_SCHEMA)
    assert "praxis_block_truncate" in joined
    assert "BEFORE TRUNCATE ON facts" in joined
    assert "BEFORE TRUNCATE ON edges" in joined
    assert "FOR EACH STATEMENT" in joined
    assert "REVOKE TRUNCATE ON facts FROM PUBLIC" in joined
    assert "REVOKE TRUNCATE ON edges FROM PUBLIC" in joined
