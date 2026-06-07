"""SEC-4 / invariant 8: actuation needs a human gate once a session holds untrusted content."""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.context import ServerContext, TrifectaViolation
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy, Tier
from praxis.store import SqliteStore


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def test_act_requires_gate_after_untrusted_read(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    # A clean session: a reversible act needs no extra gate here (the executor still
    # gates T2+ on its own).
    ctx.guard_actuation(tier=Tier.T1, approved=False)

    # Ingest attacker-influenced content (a collector read).
    ctx.mark_untrusted_ingested()

    # Now ANY actuation without the human gate (an approval) is refused.
    with pytest.raises(TrifectaViolation):
        ctx.guard_actuation(tier=Tier.T1, approved=False)
    with pytest.raises(TrifectaViolation):
        ctx.guard_actuation(tier=Tier.T2, approved=False)

    # With the human gate (an approval) it proceeds.
    ctx.guard_actuation(tier=Tier.T2, approved=True)


def test_t0_reads_are_never_gated(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()
    # A pure observation (T0) is not actuation and is never blocked.
    ctx.guard_actuation(tier=Tier.T0, approved=False)
