"""Human-gated convergence (ADR-0007; SEC-6).

A drift finding NEVER auto-fixes. ``propose`` builds a ``ConvergencePlan``, which is
inert data: constructing one actuates nothing. To act on it, the operator turns it
into an ``ExecutionRequest`` and runs it through the single audited path, where the
T2 gate enforces DRY_RUN -> approve -> execute (the executor, ADR-0005). The engine
proposes; the operator disposes.
"""

from __future__ import annotations

from dataclasses import dataclass

from praxis.drift.findings import DriftFinding
from praxis.execution.contract import Approval
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionRequest


@dataclass(frozen=True)
class ConvergencePlan:
    """A proposed remediation. Inert: building it has no side effect (SEC-6)."""

    finding: DriftFinding
    target: str
    command: str
    rationale: str

    def to_execution_request(
        self, *, dry_run: bool = True, approval: Approval | None = None
    ) -> ExecutionRequest:
        """Render the plan as a T2 execution request for the audited path.

        Defaults to ``dry_run=True``: the first run is always a preview. A real run
        requires a fresh approval through the executor's gate.
        """
        return ExecutionRequest(
            tool="converge",
            command=self.command,
            target=self.target,
            base_tier=Tier.T2,
            dry_run=dry_run,
            approval=approval,
            args={
                "subject": self.finding.subject,
                "predicate": self.finding.predicate,
                "kind": self.finding.kind.value,
                "rationale": self.rationale,
            },
        )


def propose(finding: DriftFinding, *, target: str, command: str, rationale: str) -> ConvergencePlan:
    """Propose a convergence for a finding. Does not actuate (SEC-6)."""
    return ConvergencePlan(finding=finding, target=target, command=command, rationale=rationale)
