"""SEC-2 / invariant 1: one ordered pipeline, audit always, approval single-use, T3 typed token."""

from __future__ import annotations

from pathlib import Path

from praxis.execution import (
    Approval,
    AuditLogger,
    ExecutionContext,
    ExecutionRequest,
    Mode,
    Policy,
    Tier,
    run,
    verify_chain,
)
from praxis.execution.audit import EMPTY_SHA256
from praxis.execution.runner import expected_token


def _ctx(tmp_path: Path, mode: Mode = Mode.OPEN) -> ExecutionContext:
    return ExecutionContext(policy=Policy(mode), audit=AuditLogger(tmp_path / "audit.jsonl"))


def _req(
    *,
    command: str,
    tool: str = "shell",
    base_tier: Tier = Tier.T1,
    target: str | None = None,
    dry_run: bool = False,
    approval: Approval | None = None,
) -> ExecutionRequest:
    return ExecutionRequest(
        tool=tool,
        command=command,
        base_tier=base_tier,
        target=target,
        dry_run=dry_run,
        approval=approval,
    )


def test_pipeline_order_and_audit_always(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ran = {"v": False}

    def execute() -> str:
        ran["v"] = True
        return "should not run"

    # A deny-listed command is refused, the execute step never runs, and a single
    # audit record is still written (denials are audited).
    result = run(_req(command="rm -rf /", base_tier=Tier.T0), execute, context=ctx)
    assert result.ok is False
    assert result.decision.denied is True
    assert ran["v"] is False
    assert result.output == ""
    assert result.output_sha256 == EMPTY_SHA256
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").count == 1


def test_t0_read_runs_under_readonly(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.READONLY)
    req = _req(tool="collector", command="cat /etc/os-release", base_tier=Tier.T0)
    result = run(req, lambda: "Ubuntu 24.04", context=ctx)
    assert result.ok is True
    assert result.output == "Ubuntu 24.04"


def test_t2_dry_run_then_approve_then_execute(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "systemctl restart nginx"

    # Real run without approval is refused.
    no_appr = run(_req(command=cmd, target="axiom"), lambda: "done", context=ctx)
    assert no_appr.ok is False
    assert no_appr.error is not None
    assert "approval required" in no_appr.error

    # DRY_RUN is a preview and needs no approval.
    dry = run(_req(command=cmd, target="axiom", dry_run=True), lambda: "DRY", context=ctx)
    assert dry.ok is True
    assert dry.output == "DRY"

    # Approve and execute for real.
    req = _req(command=cmd, target="axiom")
    approval = Approval(action_id=req.action_id(), token=expected_token(req, Tier.T2))
    approved = run(
        _req(command=cmd, target="axiom", approval=approval), lambda: "done", context=ctx
    )
    assert approved.ok is True
    assert approved.output == "done"


def test_retry_requires_fresh_approval(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "systemctl restart nginx"
    req = _req(command=cmd, target="axiom")
    approval = Approval(action_id=req.action_id(), token=expected_token(req, Tier.T2))

    first = run(_req(command=cmd, target="axiom", approval=approval), lambda: "ok", context=ctx)
    assert first.ok is True
    # Reusing the same approval (single-use) is refused; a retry needs a fresh one.
    second = run(_req(command=cmd, target="axiom", approval=approval), lambda: "ok", context=ctx)
    assert second.ok is False
    assert second.error is not None
    assert "already used" in second.error


def test_t3_requires_typed_token_and_single_target(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "tofu destroy"

    # Multiple targets are refused at T3.
    multi = _req(command=cmd, target="axiom,atlas")
    multi_appr = Approval(action_id=multi.action_id(), token="CONFIRM-axiom,atlas")
    multi_res = run(
        _req(command=cmd, target="axiom,atlas", approval=multi_appr),
        lambda: "destroyed",
        context=ctx,
    )
    assert multi_res.ok is False
    assert multi_res.error is not None
    assert "one target" in multi_res.error

    # A single target with the correct typed token runs.
    single = _req(command=cmd, target="axiom")
    appr = Approval(action_id=single.action_id(), token=expected_token(single, Tier.T3))
    res = run(_req(command=cmd, target="axiom", approval=appr), lambda: "destroyed", context=ctx)
    assert res.ok is True
    assert res.output == "destroyed"


def test_exception_becomes_bounded_error(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)

    def boom() -> str:
        raise RuntimeError("kaboom with password=topsecret")

    result = run(_req(tool="collector", command="cat x", base_tier=Tier.T0), boom, context=ctx)
    assert result.ok is False
    assert result.error is not None
    assert "RuntimeError" in result.error
    assert "kaboom" in result.error
    assert "topsecret" not in result.error  # redacted
    assert "Traceback" not in result.error  # never a raw traceback


def test_output_body_never_in_audit(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    secret_body = "uniqueoutputmarker-do-not-log"
    run(
        _req(tool="collector", command="cat secret", base_tier=Tier.T0),
        lambda: secret_body,
        context=ctx,
    )
    ctx.audit.close()
    assert secret_body not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
