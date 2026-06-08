"""SEC-4 at the tool boundary: ``run_action`` enforces a VALIDATED human gate after
untrusted ingestion, even for a sub-T2 action. A caller-supplied token string alone
is never sufficient (this is the bypass the gate must close)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from praxis.context import ServerContext, TrifectaViolation
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.store import SqliteStore
from praxis.tools.actuate import RunActionArgs, _run_action


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def _run(args: dict[str, object], ctx: ServerContext) -> str:
    # Exercise the handler through its validated args model, the way the registry does.
    return _run_action(RunActionArgs.model_validate(args), ctx)


def _t1_args(**extra: object) -> dict[str, object]:
    args: dict[str, object] = {
        "adapter": "ssh",
        "host": "axiom",
        "host_type": "ubuntu",
        "ssh_alias": "axiom",
        "action": "uptime",  # stays T1: no sudo, no destructive verb
    }
    args.update(extra)
    return args


def _no_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    # A real (non-dry) run would shell out to ssh; make the binary lookup miss so the
    # executor turns it into a bounded error instead of touching the network.
    monkeypatch.setattr("praxis.actuation.base.shutil.which", lambda _name: None)


def test_t1_real_run_after_untrusted_needs_validated_approval(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()

    # A real T1 run with no approval is refused (the executor would not gate T1).
    with pytest.raises(TrifectaViolation):
        _run(_t1_args(dry_run=False), ctx)

    # A real T1 run with an arbitrary, unvalidated token is STILL refused: presence
    # is not validation. This is the bypass the gate closes.
    with pytest.raises(TrifectaViolation):
        _run(_t1_args(dry_run=False, approval_token="anything"), ctx)


def test_t1_proceeds_with_the_surfaced_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_real_subprocess(monkeypatch)
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()

    # The dry run surfaces the exact token the operator must supply.
    preview = json.loads(_run(_t1_args(dry_run=True), ctx))
    token = preview["approval_token"]
    assert token.startswith("APPROVE-")
    assert preview["action_id"]

    # With that validated token the trifecta gate passes (the execution itself may
    # error because ssh is not invoked here; the point is no TrifectaViolation).
    body = json.loads(_run(_t1_args(dry_run=False, approval_token=token), ctx))
    assert "ok" in body

    # The approval is single-use: replaying it is refused (SEC-2).
    with pytest.raises(TrifectaViolation):
        _run(_t1_args(dry_run=False, approval_token=token), ctx)


def test_clean_session_t1_real_run_is_not_gated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_real_subprocess(monkeypatch)
    ctx = _ctx(tmp_path)
    # No untrusted ingestion: a reversible T1 act needs no extra trifecta gate, with
    # or without a token.
    body = json.loads(_run(_t1_args(dry_run=False), ctx))
    assert "ok" in body


def test_trifecta_denial_is_audited(tmp_path: Path) -> None:
    # Invariant 3: every denial is audited, including a trifecta refusal raised out
    # of the tool handler before it reaches the executor (BL-018).
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()
    with pytest.raises(TrifectaViolation):
        _run(_t1_args(dry_run=False), ctx)
    ctx.execution.audit.close()
    records = [
        json.loads(line)
        for line in (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    denials = [r for r in records if r["decision"] == "denied"]
    assert denials, "the trifecta refusal left no audit trail"
    assert any("trifecta" in (r.get("error") or "").lower() for r in denials)
