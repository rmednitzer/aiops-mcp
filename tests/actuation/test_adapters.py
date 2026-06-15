"""Adapters wrap real tools via PATH-shimmed fakes; never call the real binary."""

from __future__ import annotations

import os
import re
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
)
from praxis.model.facts import HostType


def _ctx(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))


def _shim(bin_dir: Path, name: str, body: str, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / name
    fake.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


def _playbooks(tmp_path: Path, *names: str) -> str:
    """Create a confined playbook root with the named playbooks (BL-081)."""
    root = tmp_path / "playbooks"
    root.mkdir(parents=True, exist_ok=True)
    for name in names:
        (root / name).write_text("- hosts: all\n", encoding="utf-8")
    return str(root)


def _mint(ctx: ExecutionContext) -> str:
    """Pull the latest minted nonce out of the sink the test installed."""
    assert isinstance(ctx.approval_sink, _Sink)
    match = re.search(r"token=(\S+)", ctx.approval_sink.messages[-1])
    assert match is not None
    return match.group(1)


class _Sink:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def __call__(self, message: str) -> None:
        self.messages.append(message)


def test_ssh_t2_floor_requires_approval_even_for_benign_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # BL-073: free-form shell floors at T2; "uptime" no longer runs ungated.
    _shim(tmp_path / "bin", "ssh", 'echo "FAKE-SSH $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    denied = SSHAdapter().actuate(ubuntu, "uptime", context=ctx, dry_run=False)
    assert denied.ok is False
    assert denied.error is not None
    assert "approval required" in denied.error


def test_ssh_executes_via_path_shim_with_minted_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _shim(tmp_path / "bin", "ssh", 'echo "FAKE-SSH $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ctx.approval_sink = _Sink()
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    adapter = SSHAdapter()

    preview = adapter.actuate(ubuntu, "uptime", context=ctx, dry_run=True)
    assert preview.ok is True
    request = adapter.build_request(ubuntu, "uptime", dry_run=False)
    approval = Approval(action_id=request.action_id(), token=_mint(ctx))

    result = adapter.actuate(ubuntu, "uptime", context=ctx, dry_run=False, approval=approval)
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
    adapter = AnsibleAdapter(playbook_root=_playbooks(tmp_path, "site.yml"))
    # Ansible has a native safe preview: dry_run runs --check for real.
    result = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=True)
    assert result.ok is True
    assert "FAKE-ANSIBLE" in result.output
    assert "--check" in result.output


def test_ansible_apply_requires_then_consumes_minted_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _shim(tmp_path / "bin", "ansible-playbook", 'echo "FAKE-ANSIBLE $@"', monkeypatch)
    ctx = _ctx(tmp_path)
    ctx.approval_sink = _Sink()
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU)
    adapter = AnsibleAdapter(playbook_root=_playbooks(tmp_path, "site.yml"))

    # A real apply (T2) without approval is refused.
    denied = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=False)
    assert denied.ok is False
    assert denied.error is not None
    assert "approval required" in denied.error

    # The dry run (--check) mints; the approval binds to the REAL apply command
    # (action_key), so the preview-vs-apply argv difference does not break the
    # DRY_RUN -> approve -> execute flow (BL-072).
    preview = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=True)
    assert preview.ok is True
    request = adapter.build_request(ubuntu, "site.yml", dry_run=False)
    approval = Approval(action_id=request.action_id(), token=_mint(ctx))
    applied = adapter.actuate(ubuntu, "site.yml", context=ctx, dry_run=False, approval=approval)
    assert applied.ok is True
    assert "FAKE-ANSIBLE" in applied.output
    assert "--check" not in applied.output


def test_ansible_confines_playbooks_to_the_root(tmp_path: Path) -> None:
    # BL-081: no root configured refuses outright; an escaping path is refused.
    ubuntu = HostInfo(name="axiom", host_type=HostType.UBUNTU)
    with pytest.raises(ValueError, match="no playbook root configured"):
        AnsibleAdapter().build_argv(ubuntu, "site.yml", {}, dry_run=True)
    root = _playbooks(tmp_path, "site.yml")
    adapter = AnsibleAdapter(playbook_root=root)
    with pytest.raises(ValueError, match="escapes"):
        adapter.build_argv(ubuntu, "../../etc/passwd", {}, dry_run=True)
    with pytest.raises(ValueError, match="not found"):
        adapter.build_argv(ubuntu, "missing.yml", {}, dry_run=True)
    argv = adapter.build_argv(ubuntu, "site.yml", {}, dry_run=False)
    assert argv[0] == "ansible-playbook"
    assert argv[1] == str(Path(root) / "site.yml")


def test_ansible_rejects_option_shaped_limit_host(tmp_path: Path) -> None:
    # BL-081: the --limit value is validated even though it comes from inventory.
    adapter = AnsibleAdapter(playbook_root=_playbooks(tmp_path, "site.yml"))
    hostile = HostInfo(name="--limit-injection", host_type=HostType.UBUNTU)
    with pytest.raises(ValueError, match="unsafe ansible"):
        adapter.build_argv(hostile, "site.yml", {}, dry_run=True)


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


def test_opentofu_confines_chdir_to_the_tofu_root(tmp_path: Path) -> None:
    # BL-105: -chdir workspace selection is re-added, confined to PRAXIS_TOFU_ROOT
    # (the unconfined passthrough was removed as F-003). No root -> a chdir is refused
    # (fail closed); an escaping, missing, or non-directory target is refused; a real
    # directory under the root is emitted as the global -chdir flag before the verb.
    from praxis.actuation.opentofu import OpenTofuAdapter

    host = HostInfo(name="cloud", host_type=HostType.CLOUD)

    # No chdir requested: unchanged, with or without a configured root.
    assert OpenTofuAdapter().build_argv(host, "apply", {}, dry_run=True) == ["tofu", "plan"]

    # A chdir with no configured root is refused outright (fail closed).
    with pytest.raises(ValueError, match="no tofu root configured"):
        OpenTofuAdapter().build_argv(host, "apply", {"chdir": "live"}, dry_run=True)

    root = tmp_path / "workspaces"
    (root / "live").mkdir(parents=True)
    (root / "afile").write_text("x", encoding="utf-8")
    adapter = OpenTofuAdapter(tofu_root=str(root))

    with pytest.raises(ValueError, match="escapes"):
        adapter.build_argv(host, "apply", {"chdir": "../../etc"}, dry_run=True)
    with pytest.raises(ValueError, match="not found"):
        adapter.build_argv(host, "apply", {"chdir": "missing"}, dry_run=True)
    # -chdir takes a directory: a regular file under the root is refused.
    with pytest.raises(ValueError, match="not found"):
        adapter.build_argv(host, "apply", {"chdir": "afile"}, dry_run=True)

    expected = str((root / "live").resolve())
    assert adapter.build_argv(host, "apply", {"chdir": "live"}, dry_run=True) == [
        "tofu",
        f"-chdir={expected}",
        "plan",
    ]
    assert adapter.build_argv(host, "apply", {"chdir": "live"}, dry_run=False) == [
        "tofu",
        f"-chdir={expected}",
        "apply",
        "-auto-approve",
    ]
