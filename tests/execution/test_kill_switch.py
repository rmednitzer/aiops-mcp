"""SEC-8: the kill switch stops execution immediately and clears only on operator action."""

from __future__ import annotations

from pathlib import Path

from praxis.execution import (
    AuditLogger,
    ExecutionContext,
    ExecutionRequest,
    Mode,
    Policy,
    Tier,
    run,
)


def test_kill_switch_sentinel_is_durable_and_out_of_band(tmp_path: Path) -> None:
    # BL-075: a trip writes the sentinel, so the stop survives a restart; reset()
    # alone does not clear it (the sentinel is removed out-of-band); and an
    # operator can engage the stop by touching the file with no tool call at all.
    from praxis.execution.runner import KillSwitch

    sentinel = tmp_path / "killswitch"
    switch = KillSwitch(sentinel_path=sentinel)
    assert switch.is_tripped() is False
    switch.trip(reason="test stop")
    assert switch.is_tripped() is True
    assert sentinel.exists()
    assert "test stop" in sentinel.read_text(encoding="utf-8")

    # A "restarted" switch (fresh instance, same sentinel) is still tripped.
    restarted = KillSwitch(sentinel_path=sentinel)
    assert restarted.is_tripped() is True
    # reset clears only the in-memory trip; the sentinel still engages the stop.
    restarted.reset()
    assert restarted.is_tripped() is True
    # Removing the sentinel out-of-band restores service.
    sentinel.unlink()
    assert restarted.is_tripped() is False

    # Out-of-band engagement: touching the file trips a running switch.
    sentinel.write_text("operator: stop now\n", encoding="utf-8")
    assert restarted.is_tripped() is True


def test_emergency_stop_tool_trips_and_is_audited(tmp_path: Path) -> None:
    # BL-075: the operator-facing actuator. The trip flows through the single
    # audited path, halts subsequent execution, and works even in readonly mode
    # and in a tainted session (it is T0 and never approval-gated).
    import json

    from praxis.context import ServerContext
    from praxis.execution import ExecutionRequest, verify_chain
    from praxis.store import SqliteStore
    from praxis.tools.emergency import EmergencyStopArgs, _emergency_stop

    execution = ExecutionContext(
        policy=Policy(Mode.READONLY), audit=AuditLogger(tmp_path / "audit.jsonl")
    )
    ctx = ServerContext(execution=execution, store=SqliteStore())
    ctx.mark_untrusted_ingested()

    body = json.loads(
        _emergency_stop(EmergencyStopArgs.model_validate({"reason": "runaway loop"}), ctx)
    )
    assert body["stopped"] is True
    assert ctx.execution.kill_switch.is_tripped() is True

    # Everything after the trip is refused at step 0 of the pipeline.
    blocked = run(
        ExecutionRequest(tool="collector", command="ls", base_tier=Tier.T0),
        lambda: "data",
        context=ctx.execution,
    )
    assert blocked.ok is False
    ctx.execution.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").ok is True


def test_kill_switch_blocks_execution(tmp_path: Path) -> None:
    ctx = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))
    ran = {"v": False}

    def execute() -> str:
        ran["v"] = True
        return "did work"

    ctx.kill_switch.trip()
    req = ExecutionRequest(tool="collector", command="ls", base_tier=Tier.T0)
    blocked = run(req, execute, context=ctx)
    assert blocked.ok is False
    assert ran["v"] is False
    assert blocked.error is not None
    assert "kill switch" in blocked.error

    # Only an explicit operator reset re-enables execution.
    ctx.kill_switch.reset()
    allowed = run(req, execute, context=ctx)
    assert allowed.ok is True
    assert ran["v"] is True
