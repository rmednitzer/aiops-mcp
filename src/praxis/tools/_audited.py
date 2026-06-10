"""Route a tool body through the single audited path (invariant 1; ADR-0016).

BL-017/BL-062/BL-085: read and ingest tools no longer reach the store directly.
Each tool body runs as the ``execute`` step of ``run()``, so every tool call, read
or write, writes exactly one audit record and is subject to the kill switch, the
budget, and (for an ingest) the trifecta latch. Reads classify at T0; the ingest
classifies at T0 but is marked ``untrusted`` so it arms the session taint latch on
the audited path itself.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace

from praxis.context import ServerContext
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionRequest, run
from praxis.tools.registry import ToolError

# Read tools return structured JSON whose size is set by the store, not by a
# subprocess, so they get a larger output budget than the 64 KiB command preview.
# A body that still exceeds it is refused whole (a truncated JSON document would
# silently parse as a partial result) rather than clipped mid-object.
_READ_OUTPUT_BYTES = 8 * 1024 * 1024


def run_audited(
    ctx: ServerContext,
    *,
    tool: str,
    args: Mapping[str, object],
    execute: Callable[[], str],
    base_tier: Tier = Tier.T0,
    target: str | None = None,
    untrusted: bool = False,
) -> str:
    """Run a tool body through ``run()`` and surface failure as a ToolError.

    The audited path never raises: a failure inside ``execute`` becomes a bounded,
    audited error string, which we re-raise as a caller-facing ToolError so the MCP
    layer reports it the same as any other tool error. The audit stores only the
    output's SHA-256 and length, never the body (SEC-9); an output too large for
    the read budget is refused whole, never returned truncated mid-JSON.
    """
    request = ExecutionRequest(
        tool=tool,
        args=dict(args),
        target=target,
        base_tier=base_tier,
        untrusted=untrusted,
    )
    context = replace(ctx.execution, max_output_bytes=_READ_OUTPUT_BYTES)
    result = run(request, execute, context=context)
    if not result.ok:
        raise ToolError(result.error or f"{tool} failed")
    if result.output_len > _READ_OUTPUT_BYTES:
        raise ToolError(
            f"{tool} result is {result.output_len} bytes, over the "
            f"{_READ_OUTPUT_BYTES}-byte limit; narrow the query (the call was "
            "audited; nothing was returned truncated)"
        )
    return result.output
