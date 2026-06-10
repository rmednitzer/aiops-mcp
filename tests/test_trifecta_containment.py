"""SEC-4 / invariant 8: actuation needs a human gate once a session holds untrusted content.

Since ADR-0016 (BL-083) the containment is enforced INSIDE the single audited path:
once the shared taint latch is armed, any T1+ real run through ``run()`` requires a
server-minted approval, whatever tool handler initiated it.
"""

from __future__ import annotations

import re
from pathlib import Path

from praxis.context import ServerContext
from praxis.execution import (
    Approval,
    AuditLogger,
    ExecutionContext,
    ExecutionRequest,
    Mode,
    Policy,
    Tier,
    run,
)
from praxis.store import SqliteStore


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def _act(tier: Tier = Tier.T1, approval: Approval | None = None) -> ExecutionRequest:
    return ExecutionRequest(
        tool="collector",
        command="touch /tmp/marker",
        target="axiom",
        base_tier=tier,
        approval=approval,
    )


def test_act_requires_gate_after_untrusted_read(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    # A clean session: a reversible T1 act passes ungated (the executor still
    # gates T2+ on its own).
    clean = run(_act(), lambda: "acted", context=ctx.execution)
    assert clean.ok is True

    # Ingest attacker-influenced content (a collector read): the ServerContext
    # latch and the execution-core latch are the same state (BL-083).
    ctx.mark_untrusted_ingested()
    assert ctx.execution.taint.untrusted_ingested is True

    # Now ANY T1+ actuation without the human gate is refused, in-path, audited.
    refused = run(_act(), lambda: "acted", context=ctx.execution)
    assert refused.ok is False
    assert refused.error is not None
    assert "SEC-4" in refused.error
    refused_t2 = run(_act(tier=Tier.T2), lambda: "acted", context=ctx.execution)
    assert refused_t2.ok is False

    # With the human gate (a minted approval) it proceeds.
    minted: list[str] = []
    ctx.execution.approval_sink = minted.append
    req = _act()
    dry = run(
        ExecutionRequest(
            tool=req.tool,
            command=req.command,
            target=req.target,
            base_tier=req.base_tier,
            dry_run=True,
        ),
        lambda: "DRY",
        context=ctx.execution,
    )
    assert dry.ok is True
    match = re.search(r"token=(\S+)", minted[-1])
    assert match is not None
    approval = Approval(action_id=req.action_id(), token=match.group(1))
    gated = run(_act(approval=approval), lambda: "acted", context=ctx.execution)
    assert gated.ok is True


def test_t0_reads_are_never_gated(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()
    # A pure observation (T0) is not actuation and is never blocked.
    read = ExecutionRequest(tool="collector", command="cat /etc/os-release", base_tier=Tier.T0)
    result = run(read, lambda: "data", context=ctx.execution)
    assert result.ok is True
