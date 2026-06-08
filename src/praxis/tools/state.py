"""Read tools over the fleet-state store: query active facts and full history."""

from __future__ import annotations

import json

from pydantic import Field

from praxis.context import ServerContext
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec


class QueryFactsArgs(ToolArgs):
    subject: str | None = Field(default=None, description="Filter to one subject, e.g. host:axiom.")
    fact_type: str | None = Field(
        default=None, description="Filter to observed/desired/drift/known_good."
    )


class FactHistoryArgs(ToolArgs):
    subject: str = Field(min_length=1)
    predicate: str | None = None


def _query_facts(args: QueryFactsArgs, ctx: ServerContext) -> str:
    facts = ctx.store.list_active(subject=args.subject, fact_type=args.fact_type)
    rows: list[dict[str, object]] = [
        {"subject": f.subject, "predicate": f.predicate, "fact_type": f.fact_type, "value": f.value}
        for f in facts
    ]
    rows = ctx.filter_restricted(rows)
    return json.dumps({"count": len(rows), "facts": rows}, sort_keys=True)


def _fact_history(args: FactHistoryArgs, ctx: ServerContext) -> str:
    history = ctx.store.history(args.subject, args.predicate)
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
        tool_spec(
            name="query_facts",
            description="List active fleet-state facts; filter by subject and/or fact_type.",
            read_only=True,
            destructive=False,
            args_model=QueryFactsArgs,
            handler=_query_facts,
        )
    )
    registry.register(
        tool_spec(
            name="fact_history",
            description="Return the full recorded (bitemporal) history of facts for a subject.",
            read_only=True,
            destructive=False,
            args_model=FactHistoryArgs,
            handler=_fact_history,
        )
    )
