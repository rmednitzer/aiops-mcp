"""Drift read tool: diff observed facts against the known-good baseline.

Runs through the single audited path (BL-017/BL-062, ADR-0016). The scan reads
observed facts, which are attacker-influenced, so a scan that sees any observed
fact arms the session trifecta latch (SEC-4, invariant 8).
"""

from __future__ import annotations

import json

from pydantic import Field

from praxis.context import ServerContext
from praxis.drift import diff
from praxis.model.facts import KNOWN_GOOD, OBSERVED
from praxis.tools._audited import run_audited
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec


class DriftScanArgs(ToolArgs):
    subject: str | None = Field(default=None, description="Restrict the scan to one subject.")


def _drift_scan(args: DriftScanArgs, ctx: ServerContext) -> str:
    def execute() -> str:
        observed = ctx.store.list_active(subject=args.subject, fact_type=OBSERVED)
        ctx.mark_if_observed(observed)  # observed facts are attacker-influenced (SEC-4)
        desired = ctx.store.list_active(subject=args.subject, fact_type=KNOWN_GOOD)
        findings = diff(observed, desired, flag_unexpected=True)
        rows = [
            {
                "subject": f.subject,
                "predicate": f.predicate,
                "kind": f.kind.value,
                "severity": f.severity.value,
            }
            for f in findings
        ]
        return json.dumps({"count": len(rows), "findings": rows}, sort_keys=True)

    return run_audited(
        ctx,
        tool="drift_scan",
        args={"subject": args.subject},
        execute=execute,
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        tool_spec(
            name="drift_scan",
            description="Compute drift findings: observed facts versus the known-good baseline.",
            read_only=True,
            destructive=False,
            args_model=DriftScanArgs,
            handler=_drift_scan,
        )
    )
