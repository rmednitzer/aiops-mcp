"""The ingest tool bounds attacker-influenced telemetry at the validated boundary (BL-058).

The raw-size cap is declared on the ``IngestArgs`` model, so an oversized payload is
rejected at the trust boundary (the registry) before any collector parses it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.server import build_registry
from praxis.store import SqliteStore
from praxis.tools.collect import _MAX_RAW_CHARS, IngestArgs, _ingest
from praxis.tools.registry import ToolError


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def test_ingest_model_rejects_oversized_raw() -> None:
    huge = "x" * (_MAX_RAW_CHARS + 1)
    with pytest.raises(ValidationError):
        IngestArgs.model_validate({"collector": "probe", "subject": "host:a", "raw": huge})


def test_ingest_oversized_via_registry_is_tool_error(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    huge = "x" * (_MAX_RAW_CHARS + 1)
    with pytest.raises(ToolError):
        build_registry().call(
            "ingest_observation", {"collector": "probe", "subject": "host:a", "raw": huge}, ctx
        )
    # Nothing was ingested, so the trifecta gate was not armed by a refused payload.
    assert ctx.untrusted_ingested is False


def test_ingest_accepts_bounded_raw(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    args = IngestArgs.model_validate(
        {"collector": "probe", "subject": "host:a", "raw": "NAME=Ubuntu"}
    )
    body = json.loads(_ingest(args, ctx))
    assert body["ingested"] == 1
    assert ctx.untrusted_ingested is True
