"""Drift read tool: diff observed facts against the known-good baseline."""

from __future__ import annotations

import json

from pydantic import Field

from praxis.context import ServerContext
from praxis.drift import diff
from praxis.model.facts import KNOWN_GOOD, OBSERVED
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec


class DriftScanArgs(ToolArgs):
    subject: str | None = Field(default=None, description="Restrict the scan to one subject.")


def _drift_scan(args: DriftScanArgs, ctx: ServerContext) -> str:
    observed = ctx.store.list_active(subject=args.subject, fact_type=OBSERVED)
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
