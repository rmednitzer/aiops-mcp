"""Ingest tool: parse host telemetry into facts and record them, audited.

Collected host data is attacker-influenced, so the ingest runs through the single
audited path marked ``untrusted``: that writes one audit record (BL-085) and arms
the session trifecta latch (SEC-4, BL-083) on the path itself, not in the handler.
The 4 MiB raw body is never put in the audit args; only its SHA-256 and length are
recorded. The ingest does not change any host (read_only over the fleet), but it
does write observed facts to the model.
"""

from __future__ import annotations

import json
from typing import Literal

from pydantic import Field

from praxis.collectors import (
    AideCollector,
    CisCollector,
    Collector,
    CommandProbeCollector,
    OsqueryCollector,
    TalosCollector,
)
from praxis.context import ServerContext
from praxis.execution.audit import sha256_text
from praxis.tools._audited import run_audited
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec

# Collected telemetry is attacker-influenced; bound it before a collector parses it
# so a hostile or runaway probe cannot drive the parser to exhaust memory (BL-058).
# The bound is declared on the model, so an oversized payload is rejected at the
# boundary and nothing is ingested (the trifecta gate is not armed).
_MAX_RAW_CHARS = 4 * 1024 * 1024

CollectorName = Literal["osquery", "aide", "probe", "talos", "cis"]


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
    if kind == "cis":
        # The CIS evidence declares its own benchmark (predicate is per-control), so
        # the collector ignores the ingest predicate and reads the payload's benchmark.
        return CisCollector()
    return CommandProbeCollector(predicate)


def _ingest(args: IngestArgs, ctx: ServerContext) -> str:
    predicate = args.predicate if args.predicate else args.collector

    def execute() -> str:
        facts = _build_collector(args.collector, predicate).parse(args.raw, subject=args.subject)
        for fact in facts:
            ctx.store.put_fact(fact)
        return json.dumps(
            {"ingested": len(facts), "subject": args.subject, "collector": args.collector}
        )

    # The raw telemetry is summarized for the audit, never stored (SEC-9, BL-085).
    # untrusted=True arms the trifecta latch on the audited path (SEC-4, BL-083).
    return run_audited(
        ctx,
        tool="ingest_observation",
        args={
            "collector": args.collector,
            "subject": args.subject,
            "predicate": predicate,
            "raw_sha256": sha256_text(args.raw),
            "raw_len": len(args.raw.encode("utf-8", errors="surrogatepass")),
        },
        execute=execute,
        target=args.subject,
        untrusted=True,
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
