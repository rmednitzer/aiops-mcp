"""Adapters wrap real tools via PATH-shimmed fakes; never call the real binary."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from praxis.actuation import AnsibleAdapter, SSHAdapter
from praxis.actuation.base import HostInfo
from praxis.execution import (
    Approval,
    AuditLogger,
    ExecutionContext,
    Mode,
    Policy,
    Tier,
)
from praxis.execution.runner import expected_token
from praxis.model.facts import HostType


def _ctx(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))


def _shim(bin_dir: Path, name: str, body: str, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / name
    fake.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


def test_ssh_executes_via_path_shim(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _shim(tmp_path / "bin", "ssh", 'echo "FAKE-SSH $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    # "uptime" is T1: no approval required; run for real against the shim.
    result = SSHAdapter().actuate(ubuntu, "uptime", context=ctx, dry_run=False)
    assert result.ok is True
    # Host-key policy and BatchMode are forced into the argv (BL-020); the target
    # and action still arrive at the end.
    assert "BatchMode=yes" in result.output
    assert "StrictHostKeyChecking=accept-new" in result.output
    assert "axiom uptime" in result.output


def test_ansible_dry_run_runs_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _shim(tmp_path / "bin", "ansible-playbook", 'echo "FAKE-ANSIBLE $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU)
    # Ansible has a native safe preview: dry_run runs --check for real.
    result = AnsibleAdapter().actuate(ubuntu, "site.yml", context=ctx, dry_run=True)
    assert result.ok is True
    assert "FAKE-ANSIBLE" in result.output
    assert "--check" in result.output


def test_ansible_apply_requires_then_consumes_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _shim(tmp_path / "bin", "ansible-playbook", 'echo "FAKE-ANSIBLE $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU)
    adapter = AnsibleAdapter()

    # A real apply (T2) without approval is refused.
    denied = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=False)
    assert denied.ok is False
    assert denied.error is not None
    assert "approval required" in denied.error

    # Build the request to obtain its action id, approve it, then actuate.
    request = adapter.build_request(ubuntu, "site.yml", dry_run=False)
    approval = Approval(action_id=request.action_id(), token=expected_token(request, Tier.T2))
    applied = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=False, approval=approval)
    assert applied.ok is True
    assert "FAKE-ANSIBLE" in applied.output


def test_opentofu_dry_run_is_a_full_plan() -> None:
    # The dry-run preview must show the changes apply would make, not a -refresh-only
    # drift report, so the human approves what will actually run (invariant 6, BL-043).
    from praxis.actuation.opentofu import OpenTofuAdapter

    adapter = OpenTofuAdapter()
    host = HostInfo(name="cloud", host_type=HostType.CLOUD)
    dry = adapter.build_argv(host, "apply", {}, dry_run=True)
    assert dry == ["tofu", "plan"]
    assert "-refresh-only" not in dry
    real = adapter.build_argv(host, "apply", {}, dry_run=False)
    assert real == ["tofu", "apply", "-auto-approve"]
