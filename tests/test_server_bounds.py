"""BL-056: the stdio loop bounds reads, drops notifications, and contains hostile JSON."""

from __future__ import annotations

import io
import json
from pathlib import Path

from praxis.config import Config
from praxis.server import _MAX_LINE_CHARS, StdioServer, build_context, build_registry


def _server(tmp_path: Path) -> StdioServer:
    cfg = Config(transport="stdio", audit_path=str(tmp_path / "audit.jsonl"))
    return StdioServer(build_registry(), build_context(cfg))


def _responses(server: StdioServer, wire: str) -> list[dict[str, object]]:
    out = io.StringIO()
    server.serve(stdin=io.StringIO(wire), stdout=out)
    return [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]


def test_oversize_line_is_drained_and_refused(tmp_path: Path) -> None:
    server = _server(tmp_path)
    huge = '{"id": 1, "method": "tools/list", "pad": "' + "x" * (_MAX_LINE_CHARS + 100) + '"}\n'
    follow_up = '{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}\n'
    responses = _responses(server, huge + follow_up)
    # The oversize message is refused without buffering it, and the loop keeps
    # serving: the follow-up request still gets its real answer.
    assert any("error" in r and "too large" in str(r["error"]) for r in responses)
    assert any(r.get("id") == 2 and "result" in r for r in responses)


def test_notification_without_id_gets_no_response_even_on_error(tmp_path: Path) -> None:
    server = _server(tmp_path)
    # A request without an "id" member is a notification: silence, even for an
    # unknown method (the JSON-RPC rule the old prefix check approximated).
    responses = _responses(server, '{"jsonrpc": "2.0", "method": "does/not/exist"}\n')
    assert responses == []
    # The same method WITH an id is a request and gets the error.
    responses = _responses(server, '{"jsonrpc": "2.0", "id": 7, "method": "does/not/exist"}\n')
    assert len(responses) == 1
    assert "error" in responses[0]


def test_deeply_nested_json_is_contained(tmp_path: Path) -> None:
    server = _server(tmp_path)
    # Far beyond CPython's recursion limit, small enough to stay fast and avoid
    # platform-dependent stack behaviour at extreme depths.
    depth = 50_000
    hostile = ("[" * depth) + ("]" * depth)
    responses = _responses(server, hostile + "\n")
    assert len(responses) == 1
    assert "error" in responses[0]
