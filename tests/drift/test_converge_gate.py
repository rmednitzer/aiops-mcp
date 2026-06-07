"""SEC-6 / invariant 6: a finding never auto-fixes; convergence is DRY_RUN -> approve -> execute."""

from __future__ import annotations

from pathlib import Path

from praxis.drift import DriftFinding, DriftKind, DriftSeverity, propose
from praxis.execution import (
    Approval,
    AuditLogger,
    ExecutionContext,
    Mode,
    Policy,
    Tier,
    run,
)
from praxis.execution.runner import expected_token


def _finding() -> DriftFinding:
    return DriftFinding(
        subject="host:axiom",
        predicate="ssh_config",
        kind=DriftKind.CHANGED,
        severity=DriftSeverity.CRITICAL,
        observed={"PermitRootLogin": "yes"},
        desired={"PermitRootLogin": "no"},
    )


def test_finding_does_not_autofix() -> None:
    # Proposing a convergence is inert: it produces a plan and actuates nothing.
    plan = propose(
        _finding(),
        target="axiom",
        command="ansible-playbook ssh_hardening.yml --limit axiom",
        rationale="restore PermitRootLogin=no",
    )
    assert plan.target == "axiom"
    # The rendered request defaults to a dry run and is tier T2 (gated).
    request = plan.to_execution_request()
    assert request.dry_run is True
    assert request.base_tier == Tier.T2


def test_converge_requires_dry_run_then_approval(tmp_path: Path) -> None:
    ctx = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))
    plan = propose(
        _finding(),
        target="axiom",
        command="ansible-playbook ssh_hardening.yml --limit axiom",
        rationale="restore PermitRootLogin=no",
    )

    # A real run without approval is refused by the executor gate.
    real = plan.to_execution_request(dry_run=False)
    denied = run(real, lambda: "applied", context=ctx)
    assert denied.ok is False
    assert denied.error is not None
    assert "approval required" in denied.error

    # The dry run previews without approval.
    preview = run(
        plan.to_execution_request(dry_run=True), lambda: "would change 1 line", context=ctx
    )
    assert preview.ok is True

    # With a fresh approval, the convergence executes through the audited path.
    approval = Approval(action_id=real.action_id(), token=expected_token(real, Tier.T2))
    approved = plan.to_execution_request(dry_run=False, approval=approval)
    applied = run(approved, lambda: "applied", context=ctx)
    assert applied.ok is True
    assert applied.output == "applied"
