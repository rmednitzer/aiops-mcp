"""Restricted facts are dropped over a transport that may not see them. The
classification may be a top-level field or nested inside the fact value payload
(the shape the state tools emit), so both must be filtered."""

from __future__ import annotations

from pathlib import Path

from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.store import SqliteStore


def _ctx(tmp_path: Path, *, allow_restricted: bool) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(
        execution=execution, store=SqliteStore(), allow_restricted=allow_restricted
    )


def test_filter_drops_top_level_and_nested_restricted(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, allow_restricted=False)
    rows: list[dict[str, object]] = [
        {"subject": "a", "classification": "restricted"},  # top-level
        {"subject": "b", "value": {"classification": "restricted"}},  # nested in value
        {"subject": "c", "value": {"classification": "internal"}},  # kept
        {"subject": "d"},  # kept
    ]
    kept = ctx.filter_restricted(rows)
    assert [r["subject"] for r in kept] == ["c", "d"]


def test_filter_is_noop_when_restricted_allowed(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, allow_restricted=True)
    rows: list[dict[str, object]] = [{"subject": "a", "value": {"classification": "restricted"}}]
    assert ctx.filter_restricted(rows) == rows
