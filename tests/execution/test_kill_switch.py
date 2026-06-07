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
