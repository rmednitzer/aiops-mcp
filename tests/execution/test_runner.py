"""SEC-2 / invariant 1: one ordered pipeline, audit always, approval single-use and minted."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from praxis.execution import (
    Approval,
    AuditLogger,
    BudgetTracker,
    ExecutionContext,
    ExecutionRequest,
    Mode,
    Policy,
    Tier,
    run,
    verify_chain,
)
from praxis.execution.audit import EMPTY_SHA256


def _ctx(tmp_path: Path, mode: Mode = Mode.OPEN) -> ExecutionContext:
    return ExecutionContext(policy=Policy(mode), audit=AuditLogger(tmp_path / "audit.jsonl"))


def test_consent_ceiling_denies_actions_above_it(tmp_path: Path) -> None:
    # A per-session consent ceiling (BL-045, ADR-0041) denies, in the audited path, any
    # action classified above it; an action at or below the ceiling still runs. None (the
    # stdio default) imposes no ceiling beyond the server mode.
    ctx = ExecutionContext(
        policy=Policy(Mode.OPEN),
        audit=AuditLogger(tmp_path / "audit.jsonl"),
        consent_ceiling=Tier.T1,
    )
    high = run(_req(command="sudo reboot"), lambda: "X", context=ctx)  # classifies T3
    assert high.ok is False
    assert "consented ceiling" in (high.error or "")
    assert high.record.decision == "denied"
    # A T1 preview is at the ceiling and still runs.
    low = run(_req(command="echo hi", dry_run=True), lambda: "preview", context=ctx)
    assert low.ok is True
    ctx.audit.close()


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


def mint_approval(ctx: ExecutionContext, req: ExecutionRequest) -> Approval:
    """Run the gated DRY_RUN and capture the nonce from the out-of-band sink.

    This is the operator flow (BL-072): the token comes from the approval sink
    (the console), never from the tool result.
    """
    messages: list[str] = []
    previous_sink = ctx.approval_sink
    ctx.approval_sink = messages.append
    try:
        dry = run(replace(req, dry_run=True, approval=None), lambda: "DRY", context=ctx)
        assert dry.ok is True
        assert messages, "a gated dry run must mint an approval to the sink"
        match = re.search(r"token=(\S+)", messages[-1])
        assert match is not None
        return Approval(action_id=req.action_id(), token=match.group(1))
    finally:
        ctx.approval_sink = previous_sink


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

    # DRY_RUN is a preview, needs no approval, and mints the nonce out-of-band:
    # the token appears in the sink, never in the result (BL-072).
    minted: list[str] = []
    ctx.approval_sink = minted.append
    dry = run(_req(command=cmd, target="axiom", dry_run=True), lambda: "DRY", context=ctx)
    assert dry.ok is True
    assert dry.output == "DRY"
    assert len(minted) == 1
    token = re.search(r"token=(\S+)", minted[0])
    assert token is not None
    assert token.group(1) not in dry.output

    # Approve and execute for real with the minted nonce.
    req = _req(command=cmd, target="axiom")
    approval = Approval(action_id=req.action_id(), token=token.group(1))
    approved = run(
        _req(command=cmd, target="axiom", approval=approval), lambda: "done", context=ctx
    )
    assert approved.ok is True
    assert approved.output == "done"


def test_caller_cannot_forge_an_approval(tmp_path: Path) -> None:
    # The flaw ADR-0016 closes: a deterministic token (APPROVE-<action_id>) was
    # reproducible by the caller. Now any token not minted by the server, however
    # well-formed, is refused.
    ctx = _ctx(tmp_path, Mode.OPEN)
    req = _req(command="systemctl restart nginx", target="axiom")
    forged = Approval(action_id=req.action_id(), token=f"APPROVE-{req.action_id()}")
    result = run(replace(req, approval=forged), lambda: "done", context=ctx)
    assert result.ok is False
    assert result.error is not None
    assert "not minted" in result.error


def test_retry_requires_fresh_approval(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "systemctl restart nginx"
    req = _req(command=cmd, target="axiom")
    approval = mint_approval(ctx, req)

    first = run(replace(req, approval=approval), lambda: "ok", context=ctx)
    assert first.ok is True
    # Reusing the same approval (single-use) is refused; a retry needs a fresh one.
    second = run(replace(req, approval=approval), lambda: "ok", context=ctx)
    assert second.ok is False
    assert second.error is not None
    assert "already used" in second.error


def test_approval_is_target_bound(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "systemctl restart nginx"
    minted_for_axiom = mint_approval(ctx, _req(command=cmd, target="axiom"))
    # The same command against another target is a different action id, so the
    # binding fails on the action even before the target check.
    other = _req(command=cmd, target="atlas")
    moved = Approval(action_id=other.action_id(), token=minted_for_axiom.token)
    result = run(replace(other, approval=moved), lambda: "ok", context=ctx)
    assert result.ok is False
    assert result.error is not None


def test_approval_expires(tmp_path: Path) -> None:
    now = {"t": 1000.0}
    ctx = _ctx(tmp_path, Mode.OPEN)
    from praxis.execution.contract import ApprovalRegistry

    ctx.approvals = ApprovalRegistry(ttl_seconds=600.0, clock=lambda: now["t"])
    req = _req(command="systemctl restart nginx", target="axiom")
    approval = mint_approval(ctx, req)
    now["t"] += 601.0  # beyond the TTL
    result = run(replace(req, approval=approval), lambda: "ok", context=ctx)
    assert result.ok is False
    assert result.error is not None
    assert "expired" in result.error


def test_t3_requires_minted_token_and_single_target(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, Mode.OPEN)
    cmd = "tofu destroy"

    # Multiple targets are refused at T3, whatever the approval says.
    multi = _req(command=cmd, target="axiom,atlas")
    multi_appr = Approval(action_id=multi.action_id(), token="whatever")
    multi_res = run(replace(multi, approval=multi_appr), lambda: "destroyed", context=ctx)
    assert multi_res.ok is False
    assert multi_res.error is not None
    assert "one target" in multi_res.error

    # A single target with a minted token runs.
    single = _req(command=cmd, target="axiom")
    appr = mint_approval(ctx, single)
    res = run(replace(single, approval=appr), lambda: "destroyed", context=ctx)
    assert res.ok is True
    assert res.output == "destroyed"


def test_budget_ceiling_denies_and_is_audited(tmp_path: Path) -> None:
    # BL-074: the per-session action ceiling is enforced on the audited path.
    ctx = _ctx(tmp_path, Mode.OPEN)
    ctx.budget = BudgetTracker(max_actions=1)
    req = _req(tool="collector", command="touch /tmp/x", base_tier=Tier.T1)
    first = run(req, lambda: "ok", context=ctx)
    assert first.ok is True
    second = run(req, lambda: "ok", context=ctx)
    assert second.ok is False
    assert second.error is not None
    assert "budget exceeded" in second.error
    # T0 reads are not actions and still run after exhaustion.
    read = run(
        _req(tool="collector", command="cat /etc/os-release", base_tier=Tier.T0),
        lambda: "ok",
        context=ctx,
    )
    assert read.ok is True
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").ok is True


def test_failed_approval_does_not_burn_the_budget(tmp_path: Path) -> None:
    # Review fix (ADR-0016): the action charge happens after the gate, so a storm
    # of bad-approval calls cannot exhaust the ceiling and lock the operator out.
    ctx = _ctx(tmp_path, Mode.OPEN)
    ctx.budget = BudgetTracker(max_actions=1)
    req = _req(command="systemctl restart nginx", target="axiom")
    for _ in range(3):
        bad = run(
            replace(req, approval=Approval(action_id=req.action_id(), token="forged")),
            lambda: "no",
            context=ctx,
        )
        assert bad.ok is False
        assert "budget" not in (bad.error or "")
    assert ctx.budget.actions == 0
    approval = mint_approval(ctx, req)
    good = run(replace(req, approval=approval), lambda: "done", context=ctx)
    assert good.ok is True
    assert ctx.budget.actions == 1


def test_first_untrusted_call_is_gated_by_its_own_taint(tmp_path: Path) -> None:
    # Review fix (ADR-0016): the latch arms BEFORE the gate evaluates, so even the
    # very first untrusted T1 real run in a fresh session meets the SEC-4 gate.
    ctx = _ctx(tmp_path, Mode.OPEN)
    assert ctx.taint.untrusted_ingested is False
    req = ExecutionRequest(
        tool="collector",
        command="touch /tmp/x",
        target="axiom",
        base_tier=Tier.T1,
        untrusted=True,
    )
    first = run(req, lambda: "acted", context=ctx)
    assert first.ok is False
    assert first.error is not None
    assert "SEC-4" in first.error
    assert ctx.taint.untrusted_ingested is True


def test_mass_sql_delete_with_trailing_clause_is_t3(tmp_path: Path) -> None:
    # Review fix (ADR-0016): DELETE without WHERE classifies T3 even with a
    # trailing clause (RETURNING, LIMIT), mirroring the UPDATE pattern.
    from praxis.execution import classify

    assert classify("shell", "DELETE FROM users RETURNING *", base_tier=Tier.T1) == Tier.T3
    assert classify("shell", "DELETE FROM accounts LIMIT 100000", base_tier=Tier.T1) == Tier.T3
    assert classify("shell", "DELETE FROM users WHERE id = 1", base_tier=Tier.T1) < Tier.T3


def test_untrusted_request_arms_the_taint_latch(tmp_path: Path) -> None:
    # BL-083: run() itself arms the session latch for an untrusted-marked call.
    ctx = _ctx(tmp_path, Mode.OPEN)
    assert ctx.taint.untrusted_ingested is False
    req = ExecutionRequest(
        tool="ingest_observation", command=None, base_tier=Tier.T0, untrusted=True
    )
    result = run(req, lambda: "ingested", context=ctx)
    assert result.ok is True
    assert ctx.taint.untrusted_ingested is True


def test_tainted_session_gates_t1_actuation_in_path(tmp_path: Path) -> None:
    # SEC-4 / invariant 8 enforced inside run(): after taint, even a sub-T2 real
    # run needs a minted approval; the denial is audited.
    ctx = _ctx(tmp_path, Mode.OPEN)
    ctx.taint.mark()
    req = _req(tool="collector", command="touch /tmp/x", base_tier=Tier.T1, target="axiom")
    bare = run(req, lambda: "acted", context=ctx)
    assert bare.ok is False
    assert bare.error is not None
    assert "SEC-4" in bare.error
    # The dry run mints, and the minted approval unlocks the real run.
    approval = mint_approval(ctx, req)
    gated = run(replace(req, approval=approval), lambda: "acted", context=ctx)
    assert gated.ok is True
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").ok is True


def test_hostile_args_redaction_failure_denies_audited(tmp_path: Path) -> None:
    # BL-077: a hostile args payload that breaks redaction becomes an audited
    # denial with placeholder args, never an unaudited raise out of run().
    ctx = _ctx(tmp_path)

    class Hostile:
        def keys(self) -> list[str]:
            raise RuntimeError("hostile mapping")

        def __getitem__(self, key: str) -> object:  # pragma: no cover - keys raises
            return None

    req = ExecutionRequest(tool="collector", command="cat x", base_tier=Tier.T0, args=Hostile())  # type: ignore[arg-type]
    result = run(req, lambda: "never", context=ctx)
    assert result.ok is False
    assert result.error is not None
    assert "redaction failed" in result.error
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").count == 1


def test_deeply_nested_args_are_depth_bounded(tmp_path: Path) -> None:
    # BL-077: a deeply nested args payload is clamped, not recursed to death.
    ctx = _ctx(tmp_path)
    nested: dict[str, object] = {"leaf": "value"}
    for _ in range(200):
        nested = {"d": nested}
    req = ExecutionRequest(
        tool="collector", command="cat x", base_tier=Tier.T0, args={"deep": nested}
    )
    result = run(req, lambda: "ok", context=ctx)
    assert result.ok is True


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


def test_broken_exception_str_does_not_escape_run(tmp_path: Path) -> None:
    # A hostile or broken __str__ on the raised exception must be contained, not
    # allowed to raise out of the single audited path (invariant 1, BL-044).
    ctx = _ctx(tmp_path)

    class Hostile(Exception):
        def __str__(self) -> str:
            raise ValueError("str blew up")

    def boom() -> str:
        raise Hostile

    result = run(_req(tool="collector", command="cat x", base_tier=Tier.T0), boom, context=ctx)
    assert result.ok is False
    assert result.error is not None
    assert "Hostile" in result.error
    assert "unprintable" in result.error


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


def test_minted_token_never_in_audit_or_result(tmp_path: Path) -> None:
    # BL-072: the nonce reaches the operator sink only.
    ctx = _ctx(tmp_path, Mode.OPEN)
    minted: list[str] = []
    ctx.approval_sink = minted.append
    dry = run(
        _req(command="systemctl restart nginx", target="axiom", dry_run=True),
        lambda: "DRY",
        context=ctx,
    )
    assert dry.ok is True
    match = re.search(r"token=(\S+)", minted[0])
    assert match is not None
    token = match.group(1)
    assert token not in dry.output
    ctx.audit.close()
    assert token not in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
