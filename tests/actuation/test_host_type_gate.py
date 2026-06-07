"""SEC-5 / invariant 5: actuation branches on host_type; SSH never targets Talos."""

from __future__ import annotations

from pathlib import Path

from praxis.actuation import SSHAdapter, TalosctlAdapter
from praxis.actuation.base import HostInfo
from praxis.execution import AuditLogger, ExecutionContext, Mode, Policy
from praxis.execution.audit import verify_chain
from praxis.model.facts import HostType


def _ctx(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))


def test_ssh_refuses_talos(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    talos = HostInfo(name="k8s-01", host_type=HostType.TALOS, nodes=("100.64.0.30",))
    result = SSHAdapter().actuate(talos, "uptime", context=ctx, dry_run=True)
    assert result.ok is False
    assert result.error is not None
    assert "host_type" in result.error
    # The refusal is audited (it flows through the single audited path).
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").count == 1


def test_talosctl_refuses_ubuntu(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    result = TalosctlAdapter().actuate(ubuntu, "health", context=ctx, dry_run=True)
    assert result.ok is False
    assert result.error is not None
    assert "host_type" in result.error


def test_ssh_supports_ubuntu_dry_run_preview(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    result = SSHAdapter().actuate(ubuntu, "uptime", context=ctx, dry_run=True)
    assert result.ok is True
    assert "DRY_RUN preview" in result.output  # previewed, not executed
