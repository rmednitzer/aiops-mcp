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
from praxis.actuation.credentials import CredentialBroker
from praxis.audit import EvidenceScheduler, bind_session, select_stamper
from praxis.config import CONFIG, Config, validate_transport
from praxis.context import ServerContext
from praxis.execution.audit import AuditLogger
from praxis.execution.contract import ApprovalRegistry, BudgetTracker
from praxis.execution.policy import Policy
from praxis.execution.runner import ExecutionContext, KillSwitch, bounded_error
from praxis.store import open_store
from praxis.tools import ToolRegistry, register_all

MCP_PROTOCOL_VERSION = "2025-11-25"
_SERVER_INFO: dict[str, object] = {"name": "praxis", "version": __version__}

# A single JSON-RPC message is bounded so a hostile or runaway client cannot drive
# the stdio reader to buffer without limit (BL-056). 16 MiB is far beyond any
# legitimate tool call (the ingest body has its own 4 MiB boundary cap).
_MAX_LINE_CHARS = 16 * 1024 * 1024


def build_context(config: Config) -> ServerContext:
    store = open_store(config.store_dsn)
    # Runtime evidence (BL-076): with an audit file configured, checkpoints are
    # produced every evidence_every records via the logger's post-record hook
    # (and at shutdown via serve's finalize). The anchor high-water mark
    # (BL-050) is opt-in via PRAXIS_ANCHOR_PATH.
    audit_path = Path(config.audit_path) if config.audit_path else None
    scheduler: EvidenceScheduler | None = None
    if audit_path is not None and config.evidence_every > 0:
        evidence_path = (
            Path(config.evidence_path)
            if config.evidence_path
            else audit_path.with_suffix(".evidence.jsonl")
        )
        # Non-forgeable RFC 3161 stamping when a TSA is configured, else the offline
        # LocalStamper (BL-095, ADR-0029). select_stamper fails closed at startup if a
        # TSA URL is set without its certificate or the `tsa` extra.
        scheduler = EvidenceScheduler(
            audit_path,
            evidence_path,
            every=config.evidence_every,
            anchor_path=Path(config.anchor_path) if config.anchor_path else None,
            stamper=select_stamper(tsa_url=config.tsa_url, tsa_cert_path=config.tsa_cert_path),
        )
    audit = (
        AuditLogger(audit_path, on_record=scheduler.on_record if scheduler else None)
        if audit_path
        else AuditLogger()
    )
    # Bind the server-binary hash into the trail as the first record (ADR-0008),
    # carrying the declared audit/evidence retention tiers (BL-035, ADR-0023) so the
    # retention in force is itself part of the tamper-evident provenance.
    bind_session(audit, retention=config.retention_args)
    # Durable kill switch (BL-075), per-session budget (BL-074), and the
    # human-binding approval registry (BL-072), wired from config.
    kill_switch = KillSwitch(
        sentinel_path=Path(config.kill_switch_path) if config.kill_switch_path else None
    )
    budget = (
        BudgetTracker(max_actions=config.max_actions, max_wall_seconds=config.max_wall_seconds)
        if (config.max_actions is not None or config.max_wall_seconds is not None)
        else None
    )
    execution = ExecutionContext(
        policy=Policy(config.mode),
        audit=audit,
        kill_switch=kill_switch,
        approvals=ApprovalRegistry(ttl_seconds=float(config.approval_ttl_seconds)),
        budget=budget,
    )
    # The credential broker shares the kill switch (its kill_all trips it). It holds
    # zero grants by default, so scoped-credential enforcement is off until the
    # operator issues the first grant (BL-049).
    broker = CredentialBroker(kill_switch=kill_switch)
    return ServerContext(
        execution=execution,
        store=store,
        transport=config.transport,
        allow_restricted=config.allow_restricted,
        broker=broker,
        evidence=scheduler,
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
        # A JSON-RPC notification is a message with NO ``id`` member (not merely a
        # null id) and never receives a response (BL-056). It is also never
        # DISPATCHED here: a tools/call whose caller cannot receive the result
        # must not silently consume approvals or actuate (fail closed). The only
        # notifications MCP defines for this server are no-ops anyway.
        if "id" not in message:
            return None
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
            # Reuse the audited path's container: redacts, bounds, and survives a
            # hostile/broken __str__ so _call never raises out of the JSON-RPC loop.
            return _tool_error(bounded_error(exc))
        return {"content": [{"type": "text", "text": text}], "isError": False}

    def serve(self, stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
        source = stdin if stdin is not None else sys.stdin
        sink = stdout if stdout is not None else sys.stdout
        while True:
            # Bounded read: never buffer more than one capped message (BL-056).
            line = source.readline(_MAX_LINE_CHARS + 1)
            if line == "":
                break  # EOF
            if len(line) > _MAX_LINE_CHARS and not line.endswith("\n"):
                # An oversize message: drain the rest of the line and refuse, rather
                # than accumulate it. The id is unknowable, so reply with a null id.
                self._drain_line(source)
                _write(sink, _error(None, -32600, "request too large"))
                continue
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped)
            except json.JSONDecodeError:
                _write(sink, _error(None, -32700, "parse error"))
                continue
            except RecursionError:
                # Deeply nested JSON can exhaust the decoder's recursion limit;
                # contain it as a parse error rather than crash the loop (BL-056).
                _write(sink, _error(None, -32700, "parse error: input too deeply nested"))
                continue
            if not isinstance(message, dict):
                # JSON-RPC batch (an array) is not supported by MCP 2025-11-25;
                # any non-object is an invalid request, not a crash (BL-056).
                _write(sink, _error(None, -32600, "invalid request"))
                continue
            response = self.handle(message)
            if response is not None:
                _write(sink, response)

    @staticmethod
    def _drain_line(source: TextIO) -> None:
        """Consume the remainder of an oversize line, bounded per read (BL-056)."""
        while True:
            chunk = source.readline(_MAX_LINE_CHARS + 1)
            if chunk == "" or chunk.endswith("\n"):
                return


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
    try:
        if cfg.transport == "stdio":
            StdioServer(registry, ctx).serve()
            return
        raise NotImplementedError(
            "HTTP transport serving is staged; the transport guard (token + non-loopback "
            "opt-in + SSRF egress filter) is enforced before any bind. Use stdio for v0."
        )
    finally:
        # Cover the audit tail with a final checkpoint at orderly shutdown
        # (BL-076): verify_evidence requires full coverage at rest. An uncovered
        # tail after a crash is the intended visible seam, not a silent state.
        if ctx.evidence is not None:
            ctx.evidence.finalize()
        ctx.execution.audit.close()
