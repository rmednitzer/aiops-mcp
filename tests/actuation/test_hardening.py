"""Actuation-layer hardening: SSH host-key policy, talosctl verb/target/flag guards,
subprocess isolation, env allowlist, prompt-suppression, and path confinement
(BL-020, BL-021, BL-023, BL-024, BL-025, BL-047, BL-048, BL-080, BL-082)."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest

from praxis.actuation.base import HostInfo, run_subprocess, scrubbed_env
from praxis.actuation.runbook import RunbookAdapter
from praxis.actuation.ssh import SSHAdapter
from praxis.actuation.talosctl import TalosctlAdapter
from praxis.execution import (
    AuditLogger,
    ExecutionContext,
    Mode,
    Policy,
)
from praxis.execution.contract import Approval
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
    # by the one-target-at-a-time rule, even though host.name is a single string. The
    # refusal comes before any approval check, so no token can override it.
    ctx = _ctx(tmp_path)
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1", "10.0.0.2"))
    adapter = TalosctlAdapter()
    request = adapter.build_request(host, "reset", dry_run=False)
    approval = Approval(action_id=request.action_id(), token="irrelevant")
    result = adapter.actuate(host, "reset", context=ctx, dry_run=False, approval=approval)
    assert result.ok is False
    assert result.error is not None
    assert "one target" in result.error


def test_talosctl_single_node_target_reflects_node(tmp_path: Path) -> None:
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    request = TalosctlAdapter().build_request(host, "reset", dry_run=True)
    assert request.target == "10.0.0.1"


# --------------------------------------------------------------------- BL-082
def test_talosctl_rejects_option_tokens_in_action() -> None:
    # A post-verb token beginning with "-" can no longer smuggle a talosctl option
    # (--talosconfig redirection, --recover-skip-hash-check on a restore: BL-022).
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    adapter = TalosctlAdapter()
    with pytest.raises(ValueError, match="option not accepted"):
        adapter.build_argv(host, "get members --talosconfig /tmp/evil", {}, dry_run=False)
    with pytest.raises(ValueError, match="option not accepted"):
        adapter.build_argv(
            host, "etcd snapshot-restore --recover-skip-hash-check", {}, dry_run=False
        )


def test_talosctl_validates_nodes_and_endpoints() -> None:
    adapter = TalosctlAdapter()
    bad = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("--talosconfig=/tmp/evil",))
    with pytest.raises(ValueError, match="not an IP or RFC 1123"):
        adapter.build_argv(bad, "version", {}, dry_run=False)
    ok = HostInfo(
        name="cp",
        host_type=HostType.TALOS,
        nodes=("10.0.0.1", "fe80::1", "node-1.cluster.local"),
    )
    argv = adapter.build_argv(ok, "version", {}, dry_run=False)
    assert "--nodes" in argv


# --------------------------------------------------------------------- BL-025
def test_talosctl_reset_wipe_mode_is_explicit_and_defaults_safe() -> None:
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    adapter = TalosctlAdapter()
    # No implicit ALL: the default is system-disk, passed explicitly.
    argv = adapter.build_argv(host, "reset", {}, dry_run=False)
    assert argv[-2:] == ["--wipe-mode", "system-disk"]
    # "all" must be requested via the structured param, never via the action string.
    argv_all = adapter.build_argv(host, "reset", {"wipe_mode": "all"}, dry_run=False)
    assert argv_all[-2:] == ["--wipe-mode", "all"]
    with pytest.raises(ValueError, match="wipe_mode"):
        adapter.build_argv(host, "reset", {"wipe_mode": "everything"}, dry_run=False)


# --------------------------------------------------------------------- BL-023
def test_talosctl_upgrade_requires_passing_health_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The shimmed talosctl fails health: the real-run upgrade is refused as a HARD
    # audited precondition even with a valid approval; the dry run is not gated.
    import re as _re

    _shim(
        tmp_path / "bin",
        "talosctl",
        'if [ "$3" = "health" ]; then exit 1; fi\necho ok',
        monkeypatch,
    )
    ctx = _ctx(tmp_path)
    minted: list[str] = []
    ctx.approval_sink = minted.append
    host = HostInfo(name="cp", host_type=HostType.TALOS, nodes=("10.0.0.1",))
    adapter = TalosctlAdapter()
    preview = adapter.actuate(host, "upgrade", context=ctx, dry_run=True)
    assert preview.ok is True
    match = _re.search(r"token=(\S+)", minted[-1])
    assert match is not None
    request = adapter.build_request(host, "upgrade", dry_run=False)
    approval = Approval(action_id=request.action_id(), token=match.group(1))
    refused = adapter.actuate(host, "upgrade", context=ctx, dry_run=False, approval=approval)
    assert refused.ok is False
    assert refused.error is not None
    assert "health" in refused.error


# --------------------------------------------------------------------- BL-024
def test_runbook_confined_to_configured_root(tmp_path: Path) -> None:
    host = HostInfo(name="axiom", host_type=HostType.UBUNTU)
    with pytest.raises(ValueError, match="no runbook root configured"):
        RunbookAdapter().build_argv(host, "restart.sh", {}, dry_run=True)
    root = tmp_path / "runbooks"
    root.mkdir()
    (root / "restart.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    adapter = RunbookAdapter(runbook_root=str(root))
    with pytest.raises(ValueError, match="escapes"):
        adapter.build_argv(host, "../../../etc/passwd", {}, dry_run=True)
    argv = adapter.build_argv(host, "restart.sh", {}, dry_run=True)
    assert argv == ["bash", str(root / "restart.sh")]


# --------------------------------------------------------------------- BL-080
def test_scrubbed_env_is_an_allowlist(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unrelated server secrets must not reach wrapped tools or their plugins.
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak-me-not")
    monkeypatch.setenv("PRAXIS_HTTP_TOKEN", "leak-me-not-either")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/run/agent.sock")
    env = scrubbed_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "PRAXIS_HTTP_TOKEN" not in env
    assert env["SSH_AUTH_SOCK"] == "/run/agent.sock"  # named passthrough survives


# --------------------------------------------------------------------- BL-021
def test_scrubbed_env_suppresses_prompts() -> None:
    env = scrubbed_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["DEBIAN_FRONTEND"] == "noninteractive"
    assert env["PATH"]  # always populated


def test_scrubbed_env_overrides_empty_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # An explicitly-empty PATH must be replaced (not left empty), or tool discovery
    # via shutil.which / the subprocess PATH lookup would break.
    monkeypatch.setenv("PATH", "")
    env = scrubbed_env()
    assert env["PATH"]
    assert "/usr/bin" in env["PATH"]


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
