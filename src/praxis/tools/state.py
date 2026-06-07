"""Read tools over the fleet-state store: query active facts and full history."""

from __future__ import annotations

import json

from praxis.context import ServerContext
from praxis.tools.registry import ToolRegistry, ToolSpec

_QUERY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "subject": {"type": "string", "description": "Filter to one subject, e.g. host:axiom."},
        "fact_type": {
            "type": "string",
            "description": "Filter to observed/desired/drift/known_good.",
        },
    },
}
_HISTORY_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "subject": {"type": "string"},
        "predicate": {"type": "string"},
    },
    "required": ["subject"],
}


def _query_facts(args: dict[str, object], ctx: ServerContext) -> str:
    subject = args.get("subject")
    fact_type = args.get("fact_type")
    facts = ctx.store.list_active(
        subject=subject if isinstance(subject, str) else None,
        fact_type=fact_type if isinstance(fact_type, str) else None,
    )
    rows: list[dict[str, object]] = [
        {"subject": f.subject, "predicate": f.predicate, "fact_type": f.fact_type, "value": f.value}
        for f in facts
    ]
    rows = ctx.filter_restricted(rows)
    return json.dumps({"count": len(rows), "facts": rows}, sort_keys=True)


def _fact_history(args: dict[str, object], ctx: ServerContext) -> str:
    subject = args.get("subject")
    predicate = args.get("predicate")
    if not isinstance(subject, str):
        return json.dumps({"error": "subject is required"})
    history = ctx.store.history(subject, predicate if isinstance(predicate, str) else None)
    rows: list[dict[str, object]] = [
        {
            "predicate": f.predicate,
            "value": f.value,
            "t_recorded": f.t_recorded,
            "active": f.is_active,
        }
        for f in history
    ]
    rows = ctx.filter_restricted(rows)
    return json.dumps({"count": len(rows), "history": rows}, sort_keys=True)


def register(registry: ToolRegistry) -> None:
    registry.register(
        ToolSpec(
            name="query_facts",
            description="List active fleet-state facts; filter by subject and/or fact_type.",
            read_only=True,
            destructive=False,
            input_schema=_QUERY_SCHEMA,
            handler=_query_facts,
        )
    )
    registry.register(
        ToolSpec(
            name="fact_history",
            description="Return the full recorded (bitemporal) history of facts for a subject.",
            read_only=True,
            destructive=False,
            input_schema=_HISTORY_SCHEMA,
            handler=_fact_history,
        )
    )
