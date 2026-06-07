"""Ingest tool: parse host telemetry into facts and record them.

Collected host data is attacker-influenced, so a successful ingest marks the
session as having taken in untrusted content (SEC-4). It does not change any host
(read_only over the fleet), but it does write observed facts to the model.
"""

from __future__ import annotations

import json

from praxis.collectors import (
    AideCollector,
    Collector,
    CommandProbeCollector,
    OsqueryCollector,
    TalosCollector,
)
from praxis.context import ServerContext
from praxis.tools.registry import ToolRegistry, ToolSpec

# Collected telemetry is attacker-influenced; bound it before a collector parses it
# so a hostile or runaway probe cannot drive the parser to exhaust memory (BL-058).
_MAX_RAW_CHARS = 4 * 1024 * 1024

_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "collector": {"type": "string", "enum": ["osquery", "aide", "probe", "talos"]},
        "subject": {"type": "string"},
        "predicate": {"type": "string"},
        "raw": {"type": "string", "description": "Raw tool output captured by a T0 read."},
    },
    "required": ["collector", "subject", "raw"],
}


def _build_collector(kind: str, predicate: str) -> Collector:
    if kind == "aide":
        return AideCollector()
    if kind == "osquery":
        return OsqueryCollector(predicate)
    if kind == "talos":
        return TalosCollector(predicate)
    return CommandProbeCollector(predicate)


def _ingest(args: dict[str, object], ctx: ServerContext) -> str:
    kind = str(args.get("collector", "probe"))
    subject = str(args.get("subject", ""))
    raw = str(args.get("raw", ""))
    predicate_arg = args.get("predicate")
    predicate = predicate_arg if isinstance(predicate_arg, str) else kind
    if not subject:
        return json.dumps({"error": "subject is required"})
    if len(raw) > _MAX_RAW_CHARS:
        # Refuse oversized telemetry rather than parse it; nothing is ingested, so
        # the trifecta gate is not armed (BL-058).
        return json.dumps({"error": f"raw exceeds {_MAX_RAW_CHARS} chars; refused"})

    facts = _build_collector(kind, predicate).parse(raw, subject=subject)
    for fact in facts:
        ctx.store.put_fact(fact)
    # Collected host data is untrusted: arm the trifecta gate (SEC-4).
    ctx.mark_untrusted_ingested()
    return json.dumps({"ingested": len(facts), "subject": subject, "collector": kind})


def register(registry: ToolRegistry) -> None:
    registry.register(
        ToolSpec(
            name="ingest_observation",
            description="Parse captured host telemetry into observed facts.",
            # Writes (append-only) facts to the store, so it is not read-only; it is
            # additive, not destructive.
            read_only=False,
            destructive=False,
            input_schema=_SCHEMA,
            handler=_ingest,
        )
    )
