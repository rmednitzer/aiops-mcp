"""SEC-4 at the tool boundary: ``run_action`` is gated by the single audited path.

After untrusted ingestion, a real run needs a server-minted approval; an arbitrary
caller-supplied token string is never sufficient, and the minted token is surfaced
out-of-band only (never in the dry-run response) (BL-072, BL-083, ADR-0016).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from praxis.context import ServerContext
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.store import SqliteStore
from praxis.tools.actuate import RunActionArgs, _run_action


def _ctx(tmp_path: Path) -> ServerContext:
    execution = ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "a.jsonl"))
    return ServerContext(execution=execution, store=SqliteStore())


def _run(args: dict[str, object], ctx: ServerContext) -> str:
    # Exercise the handler through its validated args model, the way the registry does.
    return _run_action(RunActionArgs.model_validate(args), ctx)


def _ssh_args(**extra: object) -> dict[str, object]:
    args: dict[str, object] = {
        "adapter": "ssh",
        "host": "axiom",
        "host_type": "ubuntu",
        "ssh_alias": "axiom",
        "action": "uptime",
    }
    args.update(extra)
    return args


def _no_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    # A real (non-dry) run would shell out to ssh; make the binary lookup miss so the
    # executor turns it into a bounded error instead of touching the network.
    monkeypatch.setattr("praxis.actuation.base.shutil.which", lambda _name: None)


def _mint_token(ctx: ServerContext, args: dict[str, object]) -> str:
    """Run the dry run and capture the nonce from the operator sink (the BL-072 flow)."""
    minted: list[str] = []
    ctx.execution.approval_sink = minted.append
    preview = json.loads(_run({**args, "dry_run": True}, ctx))
    assert preview["ok"] is True
    assert minted, "a gated dry run must mint to the operator sink"
    match = re.search(r"token=(\S+)", minted[-1])
    assert match is not None
    token = match.group(1)
    # The nonce is out-of-band ONLY: never echoed in the tool response.
    assert token not in json.dumps(preview)
    assert "approval_token" not in preview
    return token


def test_run_action_plumbs_health_client_side_only(tmp_path: Path) -> None:
    # BL-102: the run_action tool accepts and plumbs the health_client_side_only flag.
    # The dry run exercises the tool-level plumbing; the --server=false behaviour itself
    # is proven at the adapter level (test_hardening.py).
    ctx = _ctx(tmp_path)
    ctx.execution.approval_sink = lambda _msg: None  # absorb the minted nonce
    body = json.loads(
        _run(
            {
                "adapter": "talosctl",
                "host": "cp",
                "host_type": "talos",
                "action": "upgrade",
                "nodes": ["10.0.0.1"],
                "dry_run": True,
                "health_client_side_only": True,
            },
            ctx,
        )
    )
    assert body["ok"] is True


def test_free_form_shell_floors_at_t2(tmp_path: Path) -> None:
    # BL-073: even a benign-looking free-form command via ssh is T2 and refused
    # without an approval; the patterns denylist alone is not trusted to be complete.
    ctx = _ctx(tmp_path)
    body = json.loads(_run(_ssh_args(dry_run=False), ctx))
    assert body["ok"] is False
    assert body["tier"] == "T2"
    assert "approval required" in body["error"]


def test_real_run_after_untrusted_needs_validated_approval(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()

    # A real run with no approval is refused inside the audited path.
    refused = json.loads(_run(_ssh_args(dry_run=False), ctx))
    assert refused["ok"] is False

    # A real run with an arbitrary, unminted token is STILL refused: presence
    # is not validation, and the caller cannot mint (BL-072 closes the bypass).
    forged = json.loads(_run(_ssh_args(dry_run=False, approval_token="anything"), ctx))
    assert forged["ok"] is False
    assert "not minted" in forged["error"]


def test_real_run_proceeds_with_the_minted_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _no_real_subprocess(monkeypatch)
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()

    token = _mint_token(ctx, _ssh_args())

    # With the minted token the gate passes (the execution itself errors because
    # ssh is not on PATH here; the point is the gate, not the transport).
    body = json.loads(_run(_ssh_args(dry_run=False, approval_token=token), ctx))
    assert "approval" not in (body["error"] or "")

    # The approval is single-use: replaying it is refused (SEC-2).
    replay = json.loads(_run(_ssh_args(dry_run=False, approval_token=token), ctx))
    assert replay["ok"] is False
    assert "already used" in replay["error"]


def test_dry_run_response_carries_id_but_never_the_token(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    minted: list[str] = []
    ctx.execution.approval_sink = minted.append
    preview = json.loads(_run(_ssh_args(dry_run=True), ctx))
    assert preview["ok"] is True
    assert preview["action_id"]
    assert "approval_token" not in preview
    match = re.search(r"token=(\S+)", minted[-1])
    assert match is not None
    assert match.group(1) not in json.dumps(preview)


def test_trifecta_denial_is_audited(tmp_path: Path) -> None:
    # Invariant 3: every denial is audited, now by the single path itself (BL-083
    # supersedes the handler-raised TrifectaViolation of BL-018).
    ctx = _ctx(tmp_path)
    ctx.mark_untrusted_ingested()
    refused = json.loads(_run(_ssh_args(dry_run=False), ctx))
    assert refused["ok"] is False
    ctx.execution.audit.close()
    records = [
        json.loads(line)
        for line in (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    denials = [r for r in records if r["decision"] == "denied"]
    assert denials, "the trifecta refusal left no audit trail"
    assert any("approval" in (r.get("error") or "").lower() for r in denials)
