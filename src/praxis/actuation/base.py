"""Actuation base: wrap a real tool, gate on host_type, route through the executor.

Every adapter WRAPS a tool (ssh, ansible, tofu, talosctl, a runbook); none
reinvents one. Actuation always goes through the single audited path (ADR-0005):
``actuate`` builds an ``ExecutionRequest``, adds a HARD host_type precondition
(SEC-5), and calls ``run``. So a host_type mismatch (for example SSH against a
Talos node) is refused before any command is built or executed, and the refusal is
audited.

DRY_RUN is first-class: adapters with a native safe preview (ansible ``--check``,
``tofu plan``) execute that under dry_run; adapters without one (ssh, talosctl,
runbooks) return a non-executing preview string (SEC-6).
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess  # noqa: S404 - actuation wraps real tools; calls are tier-gated and audited
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import ClassVar, Literal

from praxis.execution.contract import Approval, Contract, Predicate, Severity
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionContext, ExecutionRequest, ExecutionResult, run
from praxis.model.facts import HostType

_DEFAULT_TIMEOUT_S = 120


# A host/target must begin with an alphanumeric so it can never be parsed as a
# CLI option by the wrapped tool (a leading-dash value like ``-oProxyCommand=...``
# is an option-injection vector even with a list argv, because the tool itself
# parses it). The body permits user@host, IPv6 brackets, dots, and hyphens,
# nothing that needs a shell (BL-020; shared with ansible ``--limit``, BL-081).
SAFE_TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-\[\]:@]*$")


@dataclass(frozen=True)
class HostInfo:
    """The actuation-relevant view of an inventory host."""

    name: str
    host_type: HostType
    ssh_alias: str | None = None
    endpoints: tuple[str, ...] = ()
    nodes: tuple[str, ...] = ()


# The only server environment variables a wrapped tool receives (BL-080). The
# operator's scoped material (an SSH agent socket, a TALOSCONFIG/KUBECONFIG path)
# is passed through by name; everything else in the server environment, including
# unrelated secrets, never reaches wrapped tools or their plugins.
_ENV_ALLOWLIST = (
    "PATH",
    "HOME",  # ssh reads ~/.ssh/config for aliases; tools resolve dotfiles
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "TMPDIR",
    "SSH_AUTH_SOCK",
    "TALOSCONFIG",
    "KUBECONFIG",
    "ANSIBLE_CONFIG",
    # Vault decryption needs the password-file path; everything else ansible
    # reads from the environment can live in the ansible.cfg that ANSIBLE_CONFIG
    # names (roles_path, collections_paths, inventory, ...).
    "ANSIBLE_VAULT_PASSWORD_FILE",
)


def scrubbed_env() -> dict[str, str]:
    """An allowlisted environment for wrapped tools, with prompts suppressed.

    Only the variables in ``_ENV_ALLOWLIST`` cross from the server into a wrapped
    tool, so unrelated server secrets cannot leak into subprocesses and their
    plugins (BL-080). An MCP tool call also has no controlling TTY, so a tool that
    drops to an interactive credential or confirmation prompt would block the
    server indefinitely: the prompt-suppressing knobs are forced.
    """
    env = {key: os.environ[key] for key in _ENV_ALLOWLIST if key in os.environ}
    # Override a missing OR empty PATH: an explicit PATH="" would otherwise break
    # tool discovery (shutil.which / the subprocess PATH lookup).
    if not env.get("PATH"):
        env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    env.setdefault("LANG", "C.UTF-8")
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = ""
    env["SSH_ASKPASS"] = ""
    return env


def confine_to_root(
    action: str, *, root: str | None, kind: str, require: Literal["file", "dir"] = "file"
) -> str:
    """Resolve ``action`` to a real path inside the configured root, or refuse.

    Playbooks and runbooks execute from an operator-configured directory only
    (BL-024, BL-081); an OpenTofu workspace ``-chdir`` is confined the same way
    (BL-105). Fail closed: with no root configured the adapter refuses outright.
    Resolution follows symlinks, so a link escaping the root is refused the same as a
    ``..`` traversal. The target must exist (``require="file"`` for a playbook/runbook,
    ``require="dir"`` for a tofu workspace): a typo is an operator error surfaced here,
    not at the wrapped tool's exit status. ``require`` is a ``Literal`` so a mistyped mode
    is a static (mypy) error, not a silent fall-through to the file check.
    """
    if root is None:
        raise ValueError(
            f"no {kind} root configured; set PRAXIS_{kind.upper()}_ROOT to the "
            f"directory {kind} actuation is confined to (BL-024/BL-081/BL-105: fail closed)"
        )
    base = Path(root).resolve()
    raw = Path(action)
    candidate = (raw if raw.is_absolute() else base / raw).resolve()
    if not candidate.is_relative_to(base):
        raise ValueError(f"{kind} path escapes the configured {kind} root: {action!r}")
    exists = candidate.is_dir() if require == "dir" else candidate.is_file()
    if not exists:
        raise ValueError(f"{kind} not found under the configured {kind} root: {action!r}")
    return str(candidate)


def _kill_process_group(proc: subprocess.Popen[str]) -> None:
    """SIGKILL the child's whole process group, then the child as a fallback.

    ``start_new_session=True`` puts the child in its own group, so a tool that forks
    grandchildren (a runbook that backgrounds work) is reaped as a tree on timeout
    rather than leaking orphans that keep the server's descriptors open (BL-021).
    """
    if hasattr(os, "killpg"):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        proc.kill()
    except (ProcessLookupError, OSError):
        pass


def run_subprocess(argv: list[str], *, preview: bool, timeout_s: int = _DEFAULT_TIMEOUT_S) -> str:
    """Run a wrapped tool, or return a non-executing preview under dry-run.

    Output is returned for the executor to hash and truncate; it is never logged as
    a body (SEC-9). A non-zero child exit raises ``CalledProcessError``
    without embedding stdout/stderr, so failed actuation cannot be audited as
    successful and output bodies still do not enter error strings (BL-112). A
    missing binary raises, which the executor
    turns into a bounded error. The child runs in its own session
    (``start_new_session=True``) with stdin detached from the server's stdio
    transport (``stdin=DEVNULL``) so it can neither read the MCP wire protocol nor
    block on a prompt; on timeout the whole process group is killed (BL-021).
    """
    if preview:
        return f"DRY_RUN preview (not executed): {' '.join(argv)}"
    if shutil.which(argv[0]) is None:
        raise FileNotFoundError(f"actuation tool not found on PATH: {argv[0]}")
    proc = subprocess.Popen(  # noqa: S603 - argv is a list (no shell); tool is gated
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=scrubbed_env(),
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_process_group(proc)
        # Reap so no zombie remains; the group is already signalled.
        try:
            proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        # A bounded, output-free message: the executor wraps it as a bounded error.
        raise TimeoutError(f"actuation timed out after {timeout_s}s: {argv[0]}") from None
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, argv[0])
    return (stdout or "") + (stderr or "")


class ActuationAdapter(ABC):
    """Wraps one tool. Subclasses set the class vars and implement ``build_argv``."""

    name: ClassVar[str]
    supported: ClassVar[frozenset[HostType]]
    base_tier: ClassVar[Tier] = Tier.T1
    native_dry_run: ClassVar[bool] = False  # True if build_argv yields a safe preview argv

    @abstractmethod
    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        """Build the argv to execute (or, for native_dry_run adapters, the safe
        preview argv when dry_run)."""
        ...

    def supports(self, host: HostInfo) -> bool:
        return host.host_type in self.supported

    def extra_preconditions(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[Predicate[ExecutionRequest]]:
        """Adapter-specific HARD/SOFT preconditions merged into the audited run.

        Override to add pre-flight checks that must hold before a real run (for
        example the talosctl health gate before an upgrade, BL-023). Evaluated
        inside ``run()``, so a failure is an audited refusal.
        """
        return []

    def build_request(
        self,
        host: HostInfo,
        action: str,
        params: Mapping[str, object] | None = None,
        *,
        dry_run: bool = True,
        approval: Approval | None = None,
    ) -> ExecutionRequest:
        """Build the ExecutionRequest the executor will run. Lets a caller compute
        the action id, present the dry run, obtain an approval, then actuate.

        The action identity (``action_key``) is always the REAL-run command, so the
        approval a dry run mints binds to the command that will actually execute,
        even for adapters whose preview argv differs (ansible ``--check``, tofu
        ``plan``) (BL-072, ADR-0016).
        """
        params = params or {}
        supported = self.supports(host)
        argv = self.build_argv(host, action, params, dry_run=dry_run) if supported else []
        real_argv = (
            argv
            if not dry_run or not supported
            else self.build_argv(host, action, params, dry_run=False)
        )
        command = " ".join(argv) if supported else None
        action_key = " ".join(real_argv) if supported else None
        return ExecutionRequest(
            tool=self.name,
            command=command,
            target=host.name,
            base_tier=self.base_tier,
            dry_run=dry_run,
            approval=approval,
            args={"action": action, **dict(params)},
            action_key=action_key,
        )

    def actuate(
        self,
        host: HostInfo,
        action: str,
        params: Mapping[str, object] | None = None,
        *,
        context: ExecutionContext,
        dry_run: bool = True,
        approval: Approval | None = None,
    ) -> ExecutionResult:
        params = params or {}
        supported = self.supports(host)
        argv = self.build_argv(host, action, params, dry_run=dry_run) if supported else []
        preview = dry_run and not self.native_dry_run

        host_pred = Predicate[ExecutionRequest](
            name="host_type",
            test=lambda _req: supported,
            severity=Severity.HARD,
            message=(
                f"{self.name} does not actuate host_type={host.host_type.value} "
                f"(SEC-5; host {host.name})"
            ),
        )
        extra = self.extra_preconditions(host, action, params, dry_run=dry_run) if supported else []
        merged = Contract[ExecutionRequest](
            preconditions=[*context.contract.preconditions, host_pred, *extra],
            invariants=context.contract.invariants,
            postconditions=context.contract.postconditions,
        )
        call_context = replace(context, contract=merged)
        request = self.build_request(host, action, params, dry_run=dry_run, approval=approval)

        def execute() -> str:
            return run_subprocess(argv, preview=preview)

        return run(request, execute, context=call_context)


def make_executor(argv: list[str], *, preview: bool) -> Callable[[], str]:
    """Helper for tools that build their own argv but want the standard runner."""

    def _execute() -> str:
        return run_subprocess(argv, preview=preview)

    return _execute
