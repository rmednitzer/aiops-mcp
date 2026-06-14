"""Request-scoped audit correlation ids (BL-101, ADR-0038).

`request_id` / `client_id` are optional, additive audit fields the transport sets per
request (ambient via contextvars) and the single audited path reads, so concurrent calls
correlate to their entries without timestamp matching. They are bounded (a hostile client
cannot bloat a record) and absent outside a request scope.
"""

from __future__ import annotations

import json
from pathlib import Path

from praxis.execution import (
    AuditLogger,
    ExecutionContext,
    ExecutionRequest,
    Mode,
    Policy,
    Tier,
    run,
    verify_chain,
)
from praxis.execution.correlation import (
    MAX_ID_LEN,
    bound_id,
    current_client_id,
    current_request_id,
    request_scope,
)
from praxis.execution.patterns import PATTERNS_VERSION


def test_bound_id_coerces_and_bounds() -> None:
    assert bound_id(None) is None
    assert bound_id("") is None
    assert bound_id("   ") is None  # whitespace-only is absent
    assert bound_id("req-1") == "req-1"
    assert bound_id(12345) == "12345"  # a JSON-RPC numeric id
    assert bound_id("  spaced  ") == "spaced"
    # A hostile/oversized id is truncated, never written unbounded into the trail.
    assert bound_id("x" * (MAX_ID_LEN + 50)) == "x" * MAX_ID_LEN


def test_bound_id_survives_a_hostile_str() -> None:
    class _Hostile:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    assert bound_id(_Hostile()) is None  # contained: correlation never raises


def test_request_scope_sets_and_resets() -> None:
    assert current_request_id() is None
    assert current_client_id() is None
    with request_scope(request_id="r1", client_id="c1"):
        assert current_request_id() == "r1"
        assert current_client_id() == "c1"
        with request_scope(request_id="r2"):  # nested, client_id not inherited
            assert current_request_id() == "r2"
            assert current_client_id() is None
        assert current_request_id() == "r1"  # restored on exit
        assert current_client_id() == "c1"
    assert current_request_id() is None  # fully reset
    assert current_client_id() is None


def test_record_carries_correlation_ids_and_chain_verifies(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    rec = logger.record(
        tool="t",
        tier="T0",
        decision="allowed",
        args={},
        request_id="abc",
        client_id="cli",
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    assert rec.request_id == "abc"
    assert rec.client_id == "cli"
    written = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert written["request_id"] == "abc"
    assert written["client_id"] == "cli"
    # The new fields are inside the hashed payload, so the chain still verifies.
    assert verify_chain(log).ok is True


def test_record_defaults_correlation_ids_to_none(tmp_path: Path) -> None:
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    rec = logger.record(
        tool="t", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    logger.close()
    assert rec.request_id is None
    assert rec.client_id is None


def _ctx(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))


def _req() -> ExecutionRequest:
    return ExecutionRequest(tool="shell", command="echo hi", base_tier=Tier.T1, dry_run=True)


def test_run_stamps_the_ambient_ids_into_the_record(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    with request_scope(request_id=42, client_id="cli-7"):
        result = run(_req(), lambda: "preview", context=ctx)
    assert result.record.request_id == "42"  # the int id is coerced and bounded
    assert result.record.client_id == "cli-7"


def test_run_outside_a_scope_leaves_ids_none(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    result = run(_req(), lambda: "preview", context=ctx)
    assert result.record.request_id is None
    assert result.record.client_id is None
