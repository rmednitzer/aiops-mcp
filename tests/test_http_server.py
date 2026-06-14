"""Multi-client HTTP transport (BL-012, ADR-0041; SEC-7, invariants 6/7/8).

Socket-level tests exercise the transport mechanics (bearer auth, the session lifecycle,
the body cap, method/route handling) against a real ``HTTPServer`` on an ephemeral
loopback port, run in a background thread. They deliberately use only the store-free
methods (initialize / tools/list / error paths): the single-connection SQLite store is
same-thread in production (``serve`` runs serve_forever in the calling thread, and the
v1 server is single-threaded), so the store-touching dispatch is exercised in-thread by
``test_session_dispatch_touches_shared_store`` (the real production execution path), not
across the test's server thread.
"""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

import pytest

from praxis.config import Config
from praxis.execution.patterns import Tier
from praxis.http_server import (
    SessionManager,
    _bearer_ok,
    _parse_ceiling,
    build_http_server,
    session_context,
)
from praxis.model.facts import OBSERVED, Fact
from praxis.server import build_context, build_registry, mcp_handle

# --- unit: consent-ceiling parsing ---


def test_parse_ceiling() -> None:
    assert _parse_ceiling(None) is None
    assert _parse_ceiling({}) is None  # absent -> mode-gated, like stdio
    assert _parse_ceiling({"consentCeiling": "T2"}) is Tier.T2
    assert _parse_ceiling({"consentCeiling": "t0"}) is Tier.T0  # case-insensitive
    assert _parse_ceiling({"consentCeiling": "nonsense"}) is Tier.T0  # malformed fails closed
    assert _parse_ceiling({"consentCeiling": 5}) is Tier.T0


# --- unit: bearer auth is constant-time and strict ---


def test_bearer_ok() -> None:
    assert _bearer_ok("Bearer s3cret", "s3cret") is True
    assert _bearer_ok("Bearer wrong", "s3cret") is False
    assert _bearer_ok("s3cret", "s3cret") is False  # missing the scheme
    assert _bearer_ok(None, "s3cret") is False
    assert _bearer_ok("Bearer é", "s3cret") is False  # non-ASCII must not raise
    assert _bearer_ok("Bearer ", "") is False  # empty configured token fails closed
    assert _bearer_ok("Bearer x", "") is False


# --- unit: per-session isolation (BL-104) ---


def _base(tmp_path: Path, **kw: Any) -> Config:
    return Config(
        transport="http",
        http_token="s3cret",
        http_host="127.0.0.1",
        http_port=0,
        audit_path=str(tmp_path / "audit.jsonl"),
        **kw,
    )


def test_session_context_isolates_taint_and_approvals(tmp_path: Path) -> None:
    config = _base(tmp_path)
    base = build_context(config)
    try:
        a = session_context(base, config, ceiling=Tier.T1)
        b = session_context(base, config, ceiling=None)
        # The trifecta latch is per session: one client's ingest must not taint another.
        a.mark_untrusted_ingested()
        assert a.untrusted_ingested is True
        assert b.untrusted_ingested is False
        # Approval registries are distinct objects (a nonce minted in A is not in B).
        assert a.execution.approvals is not b.execution.approvals
        # The audit hash chain, store, and kill switch are SHARED (one trail, one stop).
        assert a.execution.audit is b.execution.audit is base.execution.audit
        assert a.store is b.store is base.store
        assert a.execution.kill_switch is b.execution.kill_switch
        # The consent ceiling rides on the per-session execution context.
        assert a.execution.consent_ceiling is Tier.T1
        assert b.execution.consent_ceiling is None
    finally:
        base.execution.audit.close()


def test_session_manager_create_get_and_evict(tmp_path: Path) -> None:
    config = _base(tmp_path)
    base = build_context(config)
    try:
        manager = SessionManager(base, config, max_sessions=3)
        sid = manager.create(Tier.T0)
        assert manager.get(sid) is not None
        assert manager.get("no-such-session") is None
        assert manager.get(None) is None
        # Bounded: creating past the cap evicts the oldest.
        for _ in range(5):
            manager.create(None)
        assert manager.count() <= 3
    finally:
        base.execution.audit.close()


def test_session_manager_get_expires_idle_session(tmp_path: Path) -> None:
    # The idle TTL must be enforced on the read path, not only lazily on create():
    # a session idle past ttl_seconds is treated as expired (returns None, 404 over HTTP)
    # and removed, never revived.
    config = _base(tmp_path)
    base = build_context(config)
    now = {"t": 1000.0}
    try:
        manager = SessionManager(
            base, config, clock=lambda: now["t"], max_sessions=8, ttl_seconds=100.0
        )
        sid = manager.create(None)
        now["t"] += 50.0
        assert manager.get(sid) is not None  # within TTL; refreshes last_seen to t=1050
        now["t"] += 50.0
        assert manager.get(sid) is not None  # 50 s since refresh, still within TTL
        now["t"] += 200.0  # 200 s idle, past the 100 s TTL
        assert manager.get(sid) is None  # expired
        assert manager.count() == 0  # and removed, not just hidden
    finally:
        base.execution.audit.close()


def test_session_dispatch_touches_shared_store(tmp_path: Path) -> None:
    # A store-touching tools/call driven through the REAL dispatch against a per-session
    # context, in-thread. This is the production execution path: the v1 HTTP server is
    # single-threaded and the single-connection SQLite store is same-thread, so the
    # request runs in the serving thread exactly as here. Proves the wired path end to
    # end (dispatch -> request_scope -> run -> classify -> the SHARED store) and that the
    # store is shared across isolated sessions: one session writes, another reads it back.
    config = _base(tmp_path)
    base = build_context(config)
    registry = build_registry()
    try:
        writer = session_context(base, config, ceiling=None)
        reader = session_context(base, config, ceiling=None)
        writer.store.put_fact(
            Fact(
                subject="host:axiom",
                predicate="os_version",
                fact_type=OBSERVED,
                value={"version": "24.04"},
                t_valid="2026-06-07T00:00:00.000000Z",
                actor="test",
            )
        )
        resp = mcp_handle(
            {"id": 3, "method": "tools/call", "params": {"name": "query_facts", "arguments": {}}},
            registry,
            reader,
            client_id="session-xyz",
        )
        assert resp is not None
        result = cast(dict[str, Any], resp["result"])
        assert result["isError"] is False
        body = json.loads(result["content"][0]["text"])
        assert body["count"] == 1  # the shared store is reachable through the session dispatch
    finally:
        base.execution.audit.close()


# --- integration: a real server on an ephemeral loopback port ---


@contextmanager
def _running(tmp_path: Path, **kw: Any) -> Iterator[int]:
    config = _base(tmp_path, **kw)
    base = build_context(config)
    httpd = build_http_server(config, base, build_registry(), mcp_handle)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield int(httpd.server_address[1])
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        base.execution.audit.close()


def _post(
    port: int,
    body: object,
    *,
    token: str | None = "s3cret",  # noqa: S107 - loopback test token, not a real secret
    session: str | None = None,
    method: str = "POST",
) -> tuple[int, dict[str, str], Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=data, method=method)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    if session is not None:
        req.add_header("Mcp-Session-Id", session)
    try:
        resp = urllib.request.urlopen(req, timeout=5)  # noqa: S310 - loopback test client
        raw = resp.read()
        return resp.status, dict(resp.headers), (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, dict(exc.headers), (json.loads(raw) if raw else None)


def _init(port: int) -> str:
    status, headers, body = _post(port, {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert status == 200, body
    assert body["result"]["protocolVersion"]
    return headers["Mcp-Session-Id"]


def test_http_requires_bearer_token(tmp_path: Path) -> None:
    with _running(tmp_path) as port:
        status, _, body = _post(
            port, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, token=None
        )
        assert status == 401
        status, _, _ = _post(
            port, {"jsonrpc": "2.0", "id": 1, "method": "initialize"}, token="wrong"
        )
        assert status == 401


def test_http_initialize_issues_session_and_tools_list(tmp_path: Path) -> None:
    with _running(tmp_path) as port:
        session = _init(port)
        assert session
        status, _, body = _post(
            port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, session=session
        )
        assert status == 200
        assert isinstance(body["result"]["tools"], list)
        assert body["result"]["tools"]  # the registry is non-empty


def test_http_request_without_session_is_404(tmp_path: Path) -> None:
    with _running(tmp_path) as port:
        status, _, body = _post(port, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert status == 404
        assert "session not found" in body["error"]["message"]


def test_http_initialize_without_id_mints_no_session(tmp_path: Path) -> None:
    # An id-less "initialize" is a JSON-RPC notification: it must not mint a session (no
    # slot churn or eviction of other clients) and is acked with 202, no Mcp-Session-Id.
    config = _base(tmp_path)
    base = build_context(config)
    httpd = build_http_server(config, base, build_registry(), mcp_handle)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        port = int(httpd.server_address[1])
        status, headers, body = _post(port, {"jsonrpc": "2.0", "method": "initialize"})
        assert status == 202
        assert "Mcp-Session-Id" not in headers
        assert body is None
        assert httpd.manager.count() == 0  # no session slot leaked by a notification
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)
        base.execution.audit.close()


def test_http_oversize_body_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("praxis.http_server._HTTP_BODY_MAX", 16)
    with _running(tmp_path) as port:
        status, _, body = _post(
            port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"x": "y" * 100}}
        )
        assert status == 413
        assert "too large" in body["error"]["message"]


def test_http_get_is_method_not_allowed(tmp_path: Path) -> None:
    with _running(tmp_path) as port:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", method="GET")
        req.add_header("Authorization", "Bearer s3cret")
        try:
            urllib.request.urlopen(req, timeout=5)  # noqa: S310 - loopback test client
            raise AssertionError("GET should be rejected")
        except urllib.error.HTTPError as exc:
            assert exc.code == 405


def test_http_unknown_session_after_token_is_404(tmp_path: Path) -> None:
    # A valid token but a forged/expired session id is refused (per-session isolation).
    with _running(tmp_path) as port:
        status, _, _ = _post(
            port, {"jsonrpc": "2.0", "id": 9, "method": "tools/list"}, session="forged-session-id"
        )
        assert status == 404
