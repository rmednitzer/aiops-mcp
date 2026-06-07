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

import shutil
import subprocess  # noqa: S404 - actuation wraps real tools; calls are tier-gated and audited
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import ClassVar

from praxis.execution.contract import Approval, Contract, Predicate, Severity
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionContext, ExecutionRequest, ExecutionResult, run
from praxis.model.facts import HostType

_DEFAULT_TIMEOUT_S = 120


@dataclass(frozen=True)
class HostInfo:
    """The actuation-relevant view of an inventory host."""

    name: str
    host_type: HostType
    ssh_alias: str | None = None
    endpoints: tuple[str, ...] = ()
    nodes: tuple[str, ...] = ()


def run_subprocess(argv: list[str], *, preview: bool, timeout_s: int = _DEFAULT_TIMEOUT_S) -> str:
    """Run a wrapped tool, or return a non-executing preview under dry-run.

    Output is returned for the executor to hash and truncate; it is never logged as
    a body (SEC-9). A missing binary raises, which the executor turns into a
    bounded error.
    """
    if preview:
        return f"DRY_RUN preview (not executed): {' '.join(argv)}"
    if shutil.which(argv[0]) is None:
        raise FileNotFoundError(f"actuation tool not found on PATH: {argv[0]}")
    completed = subprocess.run(  # noqa: S603 - argv is a list (no shell); tool is gated
        argv,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        check=False,
    )
    return (completed.stdout or "") + (completed.stderr or "")


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
        the action id, present the dry run, obtain an approval, then actuate."""
        params = params or {}
        supported = self.supports(host)
        argv = self.build_argv(host, action, params, dry_run=dry_run) if supported else []
        command = " ".join(argv) if supported else None
        return ExecutionRequest(
            tool=self.name,
            command=command,
            target=host.name,
            base_tier=self.base_tier,
            dry_run=dry_run,
            approval=approval,
            args={"action": action, **dict(params)},
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
        merged = Contract[ExecutionRequest](
            preconditions=[*context.contract.preconditions, host_pred],
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
