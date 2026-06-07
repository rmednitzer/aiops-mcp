"""The stdio MCP server: dispatch, annotations, and that output bodies are not logged (DoD)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

import praxis
from praxis.config import Config
from praxis.context import ServerContext
from praxis.model.facts import OBSERVED, Fact
from praxis.server import StdioServer, build_context, build_registry
from praxis.tools import REGISTERED_TOOLS


def _server(tmp_path: Path) -> tuple[StdioServer, ServerContext]:
    cfg = Config(transport="stdio", audit_path=str(tmp_path / "audit.jsonl"))
    ctx = build_context(cfg)
    return StdioServer(build_registry(), ctx), ctx


def _result(resp: dict[str, object] | None) -> dict[str, Any]:
    assert resp is not None
    return cast(dict[str, Any], resp["result"])


def test_initialize_reports_server_info(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    resp = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    result = _result(resp)
    assert result["serverInfo"] == {"name": "praxis", "version": praxis.__version__}


def test_tools_list_carries_accurate_annotations(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    result = _result(server.handle({"id": 2, "method": "tools/list"}))
    tools = {t["name"]: t for t in result["tools"]}
    assert set(tools) == set(REGISTERED_TOOLS)
    assert tools["run_action"]["annotations"]["destructiveHint"] is True
    assert tools["run_action"]["annotations"]["readOnlyHint"] is False
    assert tools["query_facts"]["annotations"]["readOnlyHint"] is True


def test_tools_call_query_facts(tmp_path: Path) -> None:
    server, ctx = _server(tmp_path)
    ctx.store.put_fact(
        Fact(
            subject="host:axiom",
            predicate="os_version",
            fact_type=OBSERVED,
            value={"version": "24.04"},
            t_valid="2026-06-07T00:00:00.000000Z",
            actor="test",
        )
    )
    result = _result(
        server.handle(
            {"id": 3, "method": "tools/call", "params": {"name": "query_facts", "arguments": {}}}
        )
    )
    assert result["isError"] is False
    body = json.loads(result["content"][0]["text"])
    assert body["count"] == 1


def test_unknown_method_is_jsonrpc_error(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    resp = server.handle({"id": 4, "method": "does/not/exist"})
    assert resp is not None
    assert "error" in resp


def test_notifications_get_no_response(tmp_path: Path) -> None:
    server, _ = _server(tmp_path)
    assert server.handle({"method": "notifications/initialized"}) is None


def test_run_action_dry_run_body_not_in_audit(tmp_path: Path) -> None:
    audit_path = tmp_path / "audit.jsonl"
    ctx = build_context(Config(transport="stdio", audit_path=str(audit_path)))
    server = StdioServer(build_registry(), ctx)
    result = _result(
        server.handle(
            {
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "run_action",
                    "arguments": {
                        "adapter": "ssh",
                        "host": "axiom",
                        "host_type": "ubuntu",
                        "ssh_alias": "axiom",
                        "action": "uptime",
                        "dry_run": True,
                    },
                },
            }
        )
    )
    assert result["isError"] is False
    ctx.execution.audit.close()
    # The output preview body is never written to the audit log (SEC-9).
    assert "DRY_RUN preview" not in audit_path.read_text(encoding="utf-8")


def test_tool_error_text_is_redacted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # An exception escaping the registry must not return a secret to the client; the
    # bounded tool error string is redacted before it leaves the server (BL-041).
    server, ctx = _server(tmp_path)

    def boom(name: str, args: dict[str, object], ctx: ServerContext) -> str:
        raise RuntimeError("connect failed password=supersecretvalue")

    monkeypatch.setattr(server.registry, "call", boom)
    resp = cast(dict[str, Any], server._call({"name": "query_facts", "arguments": {}}))
    assert resp["isError"] is True
    text = resp["content"][0]["text"]
    assert "supersecretvalue" not in text
    assert "RuntimeError" in text
