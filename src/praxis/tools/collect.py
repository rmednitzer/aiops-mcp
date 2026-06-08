"""Ingest tool: parse host telemetry into facts and record them.

Collected host data is attacker-influenced, so a successful ingest marks the
session as having taken in untrusted content (SEC-4). It does not change any host
(read_only over the fleet), but it does write observed facts to the model.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from praxis.collectors import (
    AideCollector,
    Collector,
    CommandProbeCollector,
    OsqueryCollector,
    TalosCollector,
)
from praxis.context import ServerContext
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec

# Collected telemetry is attacker-influenced; bound it before a collector parses it
# so a hostile or runaway probe cannot drive the parser to exhaust memory (BL-058).
# The bound is declared on the model, so an oversized payload is rejected at the
# boundary and nothing is ingested (the trifecta gate is not armed).
_MAX_RAW_CHARS = 4 * 1024 * 1024

CollectorName = Literal["osquery", "aide", "probe", "talos"]


class IngestArgs(ToolArgs):
    collector: CollectorName
    subject: str = Field(min_length=1)
    raw: str = Field(
        max_length=_MAX_RAW_CHARS, description="Raw tool output captured by a T0 read."
    )
    predicate: str | None = None


def _build_collector(kind: CollectorName, predicate: str) -> Collector:
    if kind == "aide":
        return AideCollector()
    if kind == "osquery":
        return OsqueryCollector(predicate)
    if kind == "talos":
        return TalosCollector(predicate)
    return CommandProbeCollector(predicate)


def _ingest(args: IngestArgs, ctx: ServerContext) -> str:
    predicate = args.predicate if args.predicate else args.collector
    facts = _build_collector(args.collector, predicate).parse(args.raw, subject=args.subject)
    for fact in facts:
        ctx.store.put_fact(fact)
    # Collected host data is untrusted: arm the trifecta gate (SEC-4).
    ctx.mark_untrusted_ingested()
    return json.dumps(
        {"ingested": len(facts), "subject": args.subject, "collector": args.collector}
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        tool_spec(
            name="ingest_observation",
            description="Parse captured host telemetry into observed facts.",
            # Writes (append-only) facts to the store, so it is not read-only; it is
            # additive, not destructive.
            read_only=False,
            destructive=False,
            args_model=IngestArgs,
            handler=_ingest,
        )
    )
