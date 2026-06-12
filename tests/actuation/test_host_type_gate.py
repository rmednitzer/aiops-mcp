"""SEC-5 / invariant 5: actuation branches on host_type; SSH never targets Talos."""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.actuation import (
    AnsibleAdapter,
    OpenTofuAdapter,
    RunbookAdapter,
    SSHAdapter,
    TalosctlAdapter,
)
from praxis.actuation.base import ActuationAdapter, HostInfo
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


def _all_adapters() -> list[ActuationAdapter]:
    # Confinement roots deliberately unset: an unsupported host_type must be
    # refused by the HARD precondition before any argv (or root) is consulted.
    return [
        SSHAdapter(),
        AnsibleAdapter(playbook_root=None),
        OpenTofuAdapter(),
        RunbookAdapter(runbook_root=None),
        TalosctlAdapter(),
    ]


@pytest.mark.parametrize("adapter", _all_adapters(), ids=lambda a: a.name)
@pytest.mark.parametrize("host_type", list(HostType), ids=lambda h: h.value)
def test_every_adapter_refuses_every_unsupported_host_type(
    tmp_path: Path, adapter: ActuationAdapter, host_type: HostType
) -> None:
    # SEC-5 as a full matrix (BL-061): for every adapter, every host_type
    # outside its declared support set is an audited HARD refusal, decided
    # before any argv is built. Supported combinations are exercised by the
    # adapter-specific tests; this sweep pins the refusals.
    if host_type in adapter.supported:
        pytest.skip("supported combination: covered by adapter-specific tests")
    ctx = _ctx(tmp_path)
    host = HostInfo(name="m1", host_type=host_type, nodes=("198.51.100.10",))
    result = adapter.actuate(host, "noop", context=ctx, dry_run=True)
    assert result.ok is False
    assert result.error is not None
    assert "host_type" in result.error
    ctx.audit.close()
    assert verify_chain(tmp_path / "audit.jsonl").count == 1  # the refusal is audited
