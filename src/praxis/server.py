"""MCP server wiring and transport (ADR-0006; SEC-7).

Assembles the store, the executor, and the ServerContext, enforces the transport
guard (fails closed on an unsafe HTTP bind), and serves the tool registry. The
stdio transport is a self-contained, newline-delimited JSON-RPC 2.0 loop
(initialize / tools/list / tools/call), so the default deployment needs no
third-party server and exposes no network surface. HTTP serving is staged behind
the (enforced) guard; see LIMITATIONS.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from praxis import __version__
from praxis.audit import bind_session
from praxis.config import CONFIG, Config, validate_transport
from praxis.context import ServerContext
from praxis.execution.audit import AuditLogger
from praxis.execution.policy import Policy
from praxis.execution.runner import ExecutionContext
from praxis.store import open_store
from praxis.tools import ToolRegistry, register_all

MCP_PROTOCOL_VERSION = "2025-11-25"
_SERVER_INFO: dict[str, object] = {"name": "praxis", "version": __version__}


def build_context(config: Config) -> ServerContext:
    store = open_store(config.store_dsn)
    audit = AuditLogger(Path(config.audit_path)) if config.audit_path else AuditLogger()
    # Bind the server-binary hash into the trail as the first record (ADR-0008).
    bind_session(audit)
    execution = ExecutionContext(policy=Policy(config.mode), audit=audit)
    return ServerContext(
        execution=execution,
        store=store,
        transport=config.transport,
        allow_restricted=config.allow_restricted,
    )


def build_registry() -> ToolRegistry:
    registry = ToolRegistry()
    register_all(registry)
    return registry


class StdioServer:
    """A minimal JSON-RPC 2.0 server over newline-delimited stdio messages."""

    def __init__(self, registry: ToolRegistry, ctx: ServerContext) -> None:
        self.registry = registry
        self.ctx = ctx

    def handle(self, message: Mapping[str, object]) -> dict[str, object] | None:
        method = message.get("method")
        mid = message.get("id")
        if method == "initialize":
            result: dict[str, object] = {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": _SERVER_INFO,
            }
        elif method == "tools/list":
            result = {"tools": [spec.to_mcp() for spec in self.registry.specs()]}
        elif method == "tools/call":
            result = self._call(message.get("params"))
        elif isinstance(method, str) and method.startswith("notifications/"):
            return None  # notifications get no response
        else:
            return _error(mid, -32601, f"method not found: {method!r}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def _call(self, params: object) -> dict[str, object]:
        if not isinstance(params, Mapping):
            return _tool_error("missing params")
        name = params.get("name")
        if not isinstance(name, str):
            return _tool_error("missing tool name")
        raw_args = params.get("arguments")
        args: dict[str, object] = (
            {str(k): v for k, v in raw_args.items()} if isinstance(raw_args, Mapping) else {}
        )
        try:
            text = self.registry.call(name, args, self.ctx)
        except Exception as exc:  # noqa: BLE001 - bounded; never a raw traceback to the client
            return _tool_error(f"{type(exc).__name__}: {exc}")
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        source = stdin if stdin is not None else sys.stdin
        sink = stdout if stdout is not None else sys.stdout
        for line in source:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                _write(sink, _error(None, -32700, "parse error"))
                continue
            if not isinstance(message, dict):
                _write(sink, _error(None, -32600, "invalid request"))
                continue
            response = self.handle(message)
            if response is not None:
                _write(sink, response)


def _error(mid: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _tool_error(message: str) -> dict[str, object]:
    return {"content": [{"type": "text", "text": message}], "isError": True}


def _write(sink: TextIO, payload: dict[str, object]) -> None:
    sink.write(json.dumps(payload) + "\n")
    sink.flush()


def serve(config: Config | None = None) -> None:
    """Validate the transport, build the context, and serve. Fails closed (SEC-7)."""
    cfg = config if config is not None else CONFIG
    validate_transport(cfg)
    ctx = build_context(cfg)
    registry = build_registry()
    if cfg.transport == "stdio":
        StdioServer(registry, ctx).serve()
        return
    raise NotImplementedError(
        "HTTP transport serving is staged; the transport guard (token + non-loopback "
        "opt-in + SSRF egress filter) is enforced before any bind. Use stdio for v0."
    )
