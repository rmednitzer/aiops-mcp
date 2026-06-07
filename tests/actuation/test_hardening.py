"""Actuation-layer hardening: SSH host-key policy, talosctl verb/target guards,
subprocess isolation and prompt-suppression (BL-020, BL-021, BL-047, BL-048)."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from praxis.actuation.base import HostInfo, run_subprocess, scrubbed_env
from praxis.actuation.ssh import SSHAdapter
from praxis.actuation.talosctl import TalosctlAdapter
from praxis.execution import (
    AuditLogger,
    ExecutionContext,
    Mode,
    Policy,
)
from praxis.execution.runner import expected_token
from praxis.model.facts import HostType


def _shim(bin_dir: Path, name: str, body: str, monkeypatch: pytest.MonkeyPatch) -> None:
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake = bin_dir / name
    fake.write_text(f"#!/usr/bin/env bash\n{body}\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IRWXU)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


def _ctx(tmp_path: Path) -> ExecutionContext:
    return ExecutionContext(policy=Policy(Mode.OPEN), audit=AuditLogger(tmp_path / "audit.jsonl"))


# --------------------------------------------------------------------- BL-020
def test_ssh_argv_carries_host_key_policy() -> None:
    host = HostInfo(name="axiom", host_type=HostType.UBUNTU, ssh_alias="axiom")
    argv = SSHAdapter().build_argv(host, "uptime", {}, dry_run=False)
    assert "-o" in argv
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=accept-new" in argv
    assert any(opt.startswith("ConnectTimeout=") for opt in argv)
    # Target and action arrive after the options, and the target is not option-shaped.
    assert argv[-2:] == ["axiom", "uptime"]


def test_ssh_rejects_option_injection_target() -> None:
    # A leading-dash "host" would be parsed by ssh as an option (e.g. ProxyCommand);
    # it is refused before any argv is built.
    host = HostInfo(name="-oProxyCommand=calc", host_type=HostType.UBUNTU)
    with pytest.raises(ValueError, match="unsafe ssh target"):
        SSHAdapter().build_argv(host, "uptime", {}, dry_run=False)


# --------------------------------------------------------------------- BL-048
def test_talosctl_rejects_unknown_verb() -> None:
    host = HostInfo(name="k8s", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    with pytest.raises(ValueError, match="verb not allowed"):
        TalosctlAdapter().build_argv(host, "exec --rm -- sh", {}, dry_run=False)


def test_talosctl_allows_known_verb_and_passes_flags() -> None:
    host = HostInfo(name="k8s", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    argv = TalosctlAdapter().build_argv(host, "get members", {}, dry_run=False)
    assert argv[0] == "talosctl"
    assert "--nodes" in argv
    assert argv[-2:] == ["get", "members"]


# --------------------------------------------------------------------- BL-047
def test_talosctl_t3_refuses_multiple_nodes(tmp_path: Path) -> None:
    # A destructive (T3) reset across two control-plane nodes at once must be refused
    # by the one-target-at-a-time rule, even though host.name is a single string.
    ctx = _ctx(tmp_path)
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1", "10.0.0.2"))
    adapter = TalosctlAdapter()
    request = adapter.build_request(host, "reset", dry_run=False)
    token = expected_token(request, request.base_tier)  # token shape is target-bound at T3
    from praxis.execution.contract import Approval

    approval = Approval(action_id=request.action_id(), token=token)
    result = adapter.actuate(host, "reset", context=ctx, dry_run=False, approval=approval)
    assert result.ok is False
    assert result.error is not None
    assert "one target" in result.error


def test_talosctl_single_node_target_reflects_node(tmp_path: Path) -> None:
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    request = TalosctlAdapter().build_request(host, "reset", dry_run=True)
    assert request.target == "10.0.0.1"


# --------------------------------------------------------------------- BL-021
def test_scrubbed_env_suppresses_prompts() -> None:
    env = scrubbed_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert env["PATH"]  # always populated


def test_run_subprocess_kills_process_group_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A tool that backgrounds a long-lived grandchild and exits would, without
    # process-group isolation, leak the grandchild. With start_new_session + killpg,
    # the timeout reaps the whole tree. We assert the bounded TimeoutError is raised
    # (argv-free) and that the call returns promptly rather than hanging.
    marker = tmp_path / "alive"
    _shim(
        tmp_path / "bin",
        "slowtool",
        f'touch "{marker}"\nsleep 30\n',
        monkeypatch,
    )
    start = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        run_subprocess(["slowtool"], preview=False, timeout_s=1)
    elapsed = time.monotonic() - start
    assert elapsed < 10  # killed promptly, did not wait out the 30s sleep
