"""The ingest tool bounds attacker-influenced telemetry before parsing (BL-058)."""

from __future__ import annotations

import json
from pathlib import Path

from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.store import SqliteStore
from praxis.tools.collect import _MAX_RAW_CHARS, _ingest


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def test_ingest_refuses_oversized_raw(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    huge = "x" * (_MAX_RAW_CHARS + 1)
    body = json.loads(_ingest({"collector": "probe", "subject": "host:a", "raw": huge}, ctx))
    assert "error" in body
    # Nothing was ingested, so the trifecta gate was not armed by a refused payload.
    assert ctx.untrusted_ingested is False


def test_ingest_accepts_bounded_raw(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    body = json.loads(
        _ingest({"collector": "probe", "subject": "host:a", "raw": "NAME=Ubuntu"}, ctx)
    )
    assert body["ingested"] == 1
    assert ctx.untrusted_ingested is True
