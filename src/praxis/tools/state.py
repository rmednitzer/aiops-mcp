"""Read tools over the fleet-state store: query active facts and full history.

Both reads run through the single audited path (BL-017/BL-062, ADR-0016), so each
is audit-logged like any other tool call. A read that returns observed facts (which
are attacker-influenced) arms the session trifecta latch, so reading collected data
back is treated as untrusted just like live collection (SEC-4, invariant 8).
"""

from __future__ import annotations

import json

from pydantic import Field

from praxis.context import ServerContext
from praxis.tools._audited import run_audited
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
    def execute() -> str:
        facts = ctx.store.list_active(subject=args.subject, fact_type=args.fact_type)
        ctx.mark_if_observed(facts)  # observed facts are attacker-influenced (SEC-4)
        rows: list[dict[str, object]] = [
            {
                "subject": f.subject,
                "predicate": f.predicate,
                "fact_type": f.fact_type,
                "value": f.value,
            }
            for f in facts
        ]
        rows = ctx.filter_restricted(rows)
        return json.dumps({"count": len(rows), "facts": rows}, sort_keys=True)

    return run_audited(
        ctx,
        tool="query_facts",
        args={"subject": args.subject, "fact_type": args.fact_type},
        execute=execute,
    )


def _fact_history(args: FactHistoryArgs, ctx: ServerContext) -> str:
    def execute() -> str:
        history = ctx.store.history(args.subject, args.predicate)
        ctx.mark_if_observed(history)  # observed facts are attacker-influenced (SEC-4)
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

    return run_audited(
        ctx,
        tool="fact_history",
        args={"subject": args.subject, "predicate": args.predicate},
        execute=execute,
        target=args.subject,
    )


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
