"""Multi-client HTTP transport for the MCP surface (BL-012, ADR-0006, ADR-0041; SEC-7).

Opt-in and default-closed: ``serve`` only reaches here after ``validate_transport`` has
enforced the three separately-failing guards (a bearer token, an explicit non-loopback
opt-in, and the SSRF egress filter on server-initiated requests; ADR-0006). This module
adds the serving loop the guard was staged in front of.

Design (ADR-0041, ADR-0042):
- Stdlib ``http.server`` only; no third-party web framework (dependency posture,
  ADR-0001/0014). A ``ThreadingHTTPServer`` serves each request on its own thread
  (ADR-0042, BL-110), so a slow actuation on one client does not block the others.
  Every shared component is thread-safe: the store serialises on a per-instance lock
  (@synchronized), the audit hash chain and the evidence scheduler each hold their own
  lock, and the session manager, approval registries, and budgets are lock-guarded. Per
  session ISOLATION is full (each session has its own taint latch, approval registry,
  budget, and consent ceiling), so one client's taint or pending nonce can never affect
  another.
- Sessions: ``initialize`` mints an ``Mcp-Session-Id`` and a per-session
  ``ServerContext`` sharing the global parts (the one audit hash chain, the store, the
  global kill switch, the credential broker) but with fresh per-session state. Every
  other method requires a known session id (404 otherwise). One client's trifecta taint
  or pending approval can never affect another (invariant 8, BL-104).
- Auth: every request carries ``Authorization: Bearer <token>``, compared in constant
  time (BL-106). The token is never forwarded anywhere (no passthrough; ADR-0006).
- A total request-body cap (BL-107) bounds an untrusted client; the per-client consent
  ceiling (ADR-0006 Decision 4, BL-045) is enforced in the audited path per session.
"""

from __future__ import annotations

import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING, cast

from praxis.config import Config
from praxis.context import ServerContext
from praxis.execution.contract import ApprovalRegistry, BudgetTracker
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionContext

if TYPE_CHECKING:
    from praxis.server import _Dispatch
    from praxis.tools import ToolRegistry

# Total request-body cap (BL-107): an untrusted multi-client transport must bound the
# whole message, not just iterate chunks. 16 MiB matches the stdio line cap; the ingest
# body has its own 4 MiB boundary cap inside the tool.
_HTTP_BODY_MAX = 16 * 1024 * 1024
_MAX_SESSIONS = 256
_SESSION_TTL_SECONDS = 3600.0


def _parse_ceiling(params: object) -> Tier | None:
    """Read an optional per-session consent ceiling from ``initialize`` params.

    Absent -> None (the session is gated only by the server mode, like stdio). A valid
    ``T0``..``T3`` records that ceiling. A malformed value fails closed to the most
    restrictive ceiling (T0, reads only) rather than being ignored.
    """
    if not isinstance(params, Mapping):
        return None
    raw = params.get("consentCeiling")
    if raw is None:
        return None
    name = str(raw).strip().upper()
    if name in Tier.__members__:
        return Tier[name]
    return Tier.T0


def session_context(base: ServerContext, config: Config, *, ceiling: Tier | None) -> ServerContext:
    """Derive a per-session ``ServerContext`` from the process-wide base.

    Shared (process-global): the audit logger (one hash chain over every client's
    actions), the store, the kill switch (one global stop), the credential broker, the
    evidence scheduler, the policy (immutable config), and the approval sink (the server
    console, out-of-band from the MCP channel). Fresh per session: the trifecta taint
    latch, the approval registry (a session can only consume its own nonces), the budget,
    and the consent ceiling (BL-104, BL-045).
    """
    base_exec = base.execution
    budget = (
        BudgetTracker(max_actions=config.max_actions, max_wall_seconds=config.max_wall_seconds)
        if (config.max_actions is not None or config.max_wall_seconds is not None)
        else None
    )
    execution = ExecutionContext(
        policy=base_exec.policy,
        audit=base_exec.audit,
        kill_switch=base_exec.kill_switch,
        approvals=ApprovalRegistry(ttl_seconds=base_exec.approvals.ttl_seconds),
        max_output_bytes=base_exec.max_output_bytes,
        budget=budget,
        approval_sink=base_exec.approval_sink,
        consent_ceiling=ceiling,
    )
    return ServerContext(
        execution=execution,
        store=base.store,
        transport=base.transport,
        allow_restricted=base.allow_restricted,
        broker=base.broker,
        evidence=base.evidence,
    )


@dataclass
class _Session:
    ctx: ServerContext
    ceiling: Tier | None
    last_seen: float


@dataclass
class SessionManager:
    """Thread-safe registry of per-session contexts, bounded and idle-evicting."""

    base: ServerContext
    config: Config
    clock: Callable[[], float] = time.monotonic
    max_sessions: int = _MAX_SESSIONS
    ttl_seconds: float = _SESSION_TTL_SECONDS
    _sessions: dict[str, _Session] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def create(self, ceiling: Tier | None) -> str:
        with self._lock:
            self._evict_locked()
            session_id = secrets.token_urlsafe(24)
            self._sessions[session_id] = _Session(
                ctx=session_context(self.base, self.config, ceiling=ceiling),
                ceiling=ceiling,
                last_seen=self.clock(),
            )
            return session_id

    def get(self, session_id: str | None) -> ServerContext | None:
        if not session_id:
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            now = self.clock()
            if now - session.last_seen > self.ttl_seconds:
                # Idle past the TTL: treat as expired (404), do not revive. Eviction on
                # create() is lazy and only fires when a new session is minted, so the
                # idle timeout must also be enforced here on the read path.
                del self._sessions[session_id]
                return None
            session.last_seen = now
            return session.ctx

    def count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _evict_locked(self) -> None:
        now = self.clock()
        for sid in [
            s for s, sess in self._sessions.items() if now - sess.last_seen > self.ttl_seconds
        ]:
            del self._sessions[sid]
        while len(self._sessions) >= self.max_sessions:
            oldest = min(self._sessions, key=lambda s: self._sessions[s].last_seen)
            del self._sessions[oldest]


def _bearer_ok(header: str | None, token: str) -> bool:
    """Constant-time check of an ``Authorization: Bearer`` header (BL-106)."""
    if not token:
        # An unset/empty configured token can never authenticate. validate_transport
        # already refuses to start HTTP without a token; this keeps the helper itself
        # fail-closed (compare_digest(b"", b"") is true) for any other caller.
        return False
    if not header:
        return False
    prefix = "Bearer "
    if not header.startswith(prefix):
        return False
    presented = header[len(prefix) :].strip()
    return secrets.compare_digest(
        token.encode("utf-8", "surrogatepass"), presented.encode("utf-8", "surrogatepass")
    )


class _McpHTTPServer(ThreadingHTTPServer):
    """A ``ThreadingHTTPServer`` carrying the shared dispatch state for the handler.

    Threaded so a slow actuation on one client does not block the others (ADR-0042,
    BL-110): each request runs on its own thread. Every shared component is thread-safe
    by construction: the store serialises on its lock (@synchronized), the audit hash
    chain and the evidence scheduler each hold their own lock, the session manager and
    each session's approval registry and budget are lock-guarded, and per-session
    isolation keeps one client's taint or nonce off another. ``daemon_threads`` so a
    worker never blocks process shutdown.
    """

    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        registry: ToolRegistry,
        manager: SessionManager,
        config: Config,
        dispatch: _Dispatch,
    ) -> None:
        super().__init__(address, handler)
        self.registry = registry
        self.manager = manager
        self.config = config
        self.dispatch = dispatch


class _McpHandler(BaseHTTPRequestHandler):
    """One MCP request over HTTP POST. Reads the shared state off ``self.server``."""

    protocol_version = "HTTP/1.1"
    server_version = "praxis"
    sys_version = ""  # do not leak the Python version in the Server header

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # the audit log is the record; do not write request lines to stderr

    def do_GET(self) -> None:
        # No SSE stream in v1: only POST carries MCP messages.
        self._send_json(405, _rpc_error(None, -32600, "method not allowed; POST MCP messages"))

    def do_POST(self) -> None:
        server = self._mcp_server()
        if not _bearer_ok(self.headers.get("Authorization"), server.config.http_token or ""):
            # The body is not read on an auth failure; close so an unread body cannot
            # desync a keep-alive connection (and so an unauthenticated client cannot
            # stream a body at us).
            self.close_connection = True
            self._send_json(401, _rpc_error(None, -32001, "unauthorized"))
            return
        body = self._read_body_capped()
        if body is None:
            return  # _read_body_capped already replied (411/413)
        try:
            message = json.loads(body)
        except (json.JSONDecodeError, RecursionError):
            self._send_json(200, _rpc_error(None, -32700, "parse error"))
            return
        if not isinstance(message, dict):
            self._send_json(200, _rpc_error(None, -32600, "invalid request"))
            return
        self._dispatch(server, message)

    def _dispatch(self, server: _McpHTTPServer, message: dict[str, object]) -> None:
        # A JSON-RPC notification (no "id") must have no side effects: it never mints a
        # session (so an id-less "initialize" cannot churn or evict session slots) and is
        # acknowledged with 202, never dispatched (mcp_handle returns None for it anyway).
        is_request = "id" in message
        new_session: str | None = None
        if is_request and message.get("method") == "initialize":
            new_session = server.manager.create(_parse_ceiling(message.get("params")))
            session_id: str | None = new_session
        else:
            session_id = self.headers.get("Mcp-Session-Id")
        ctx = server.manager.get(session_id)
        if ctx is None:
            if not is_request:
                self._send_status(202)  # accept the notification; no session, no side effect
                return
            self._send_json(
                404, _rpc_error(message.get("id"), -32002, "session not found; initialize first")
            )
            return
        response = server.dispatch(message, server.registry, ctx, client_id=session_id)
        if response is None:
            self._send_status(202)  # a notification: accepted, no body
            return
        # The new session id is returned only on the initialize response (MCP).
        self._send_json(200, response, session_id=new_session)

    def _read_body_capped(self) -> bytes | None:
        """Read exactly Content-Length bytes, refusing an absent or oversized length
        before reading the body (BL-107). Returns None after replying on refusal. The
        body is not consumed on refusal, so the connection is closed to keep a keep-alive
        socket from desyncing."""
        raw_len = self.headers.get("Content-Length")
        if raw_len is None:
            self.close_connection = True
            self._send_json(411, _rpc_error(None, -32600, "length required"))
            return None
        try:
            length = int(raw_len)
        except ValueError:
            self.close_connection = True
            self._send_json(400, _rpc_error(None, -32600, "invalid content-length"))
            return None
        if length < 0 or length > _HTTP_BODY_MAX:
            self.close_connection = True
            self._send_json(413, _rpc_error(None, -32600, "request too large"))
            return None
        return self.rfile.read(length)

    def _mcp_server(self) -> _McpHTTPServer:
        # self.server is always the _McpHTTPServer that constructed this handler.
        return cast(_McpHTTPServer, self.server)

    def _send_json(
        self,
        status: int,
        payload: dict[str, object],
        *,
        session_id: str | None = None,
    ) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if session_id is not None:
            self.send_header("Mcp-Session-Id", session_id)
        self.end_headers()
        self.wfile.write(body)

    def _send_status(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


def _rpc_error(mid: object, code: int, message: str) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def build_http_server(
    config: Config, base: ServerContext, registry: ToolRegistry, dispatch: _Dispatch
) -> _McpHTTPServer:
    """Bind the MCP HTTP server to the (already-vetted) address without serving. The
    caller has validated the transport guard (token + non-loopback opt-in); a port of 0
    binds an ephemeral port (used by tests)."""
    manager = SessionManager(base, config)
    return _McpHTTPServer(
        (config.http_host, config.http_port),
        _McpHandler,
        registry=registry,
        manager=manager,
        config=config,
        dispatch=dispatch,
    )


def serve_http(
    config: Config, base: ServerContext, registry: ToolRegistry, dispatch: _Dispatch
) -> None:
    """Bind and serve the MCP surface over HTTP. The caller has already validated the
    transport guard (token + non-loopback opt-in); this only binds the vetted address."""
    httpd = build_http_server(config, base, registry, dispatch)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
