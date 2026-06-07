"""Drift read tool: diff observed facts against the known-good baseline."""

from __future__ import annotations

import json

from praxis.context import ServerContext
from praxis.drift import diff
from praxis.model.facts import KNOWN_GOOD, OBSERVED
from praxis.tools.registry import ToolRegistry, ToolSpec

_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "subject": {"type": "string", "description": "Restrict the scan to one subject."}
    },
}


def _drift_scan(args: dict[str, object], ctx: ServerContext) -> str:
    subject = args.get("subject")
    subj = subject if isinstance(subject, str) else None
    observed = ctx.store.list_active(subject=subj, fact_type=OBSERVED)
    desired = ctx.store.list_active(subject=subj, fact_type=KNOWN_GOOD)
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
        ToolSpec(
            name="drift_scan",
            description="Compute drift findings: observed facts versus the known-good baseline.",
            read_only=True,
            destructive=False,
            input_schema=_SCHEMA,
            handler=_drift_scan,
        )
    )
