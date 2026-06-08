"""ADR-0014: MCP tool arguments are validated at the boundary by the args model.

The pydantic model behind each tool is the single source of truth for both the
advertised JSON Schema and the parse/validate step, so an out-of-shape, missing,
unknown-enum, or unexpected argument is rejected once at the registry boundary
(``ToolError``) rather than reaching a handler.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.server import build_registry
from praxis.store import SqliteStore
from praxis.tools.registry import ToolError, ToolRegistry


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def _registry() -> ToolRegistry:
    return build_registry()


def test_unknown_adapter_is_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError, match="adapter"):
        _registry().call(
            "run_action",
            {"adapter": "telnet", "host": "h", "host_type": "ubuntu", "action": "x"},
            ctx,
        )


def test_unknown_host_type_is_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError, match="host_type"):
        _registry().call(
            "run_action",
            {"adapter": "ssh", "host": "h", "host_type": "bsd", "action": "x"},
            ctx,
        )


def test_missing_required_argument_is_rejected(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError, match="action"):
        _registry().call(
            "run_action",
            {"adapter": "ssh", "host": "h", "host_type": "ubuntu"},  # no action
            ctx,
        )


def test_unexpected_argument_is_rejected(tmp_path: Path) -> None:
    # extra='forbid': an unexpected field fails closed instead of being ignored.
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError):
        _registry().call("query_facts", {"subject": "host:a", "surprise": 1}, ctx)


def test_fact_history_requires_subject(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError, match="subject"):
        _registry().call("fact_history", {}, ctx)


def test_strict_mode_rejects_coerced_types(tmp_path: Path) -> None:
    # Strict validation: a JSON string is not a boolean, so it is rejected rather than
    # silently coerced, keeping runtime acceptance identical to the advertised schema.
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError):
        _registry().call(
            "run_action",
            {
                "adapter": "ssh",
                "host": "h",
                "host_type": "ubuntu",
                "action": "x",
                "dry_run": "false",
            },
            ctx,
        )


def test_unknown_tool_is_tool_error(tmp_path: Path) -> None:
    # An unknown tool is a bounded ToolError at the boundary, not a raw KeyError.
    ctx = _ctx(tmp_path)
    with pytest.raises(ToolError, match="unknown tool"):
        _registry().call("does_not_exist", {}, ctx)


def test_valid_arguments_dispatch(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    # A well-formed read call validates and returns a result (no raise).
    out = _registry().call("query_facts", {"subject": "host:a"}, ctx)
    assert '"count"' in out
