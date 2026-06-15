"""The MCP tool surface (BL-012). The read tools, an observation-ingest tool, one
tier-gated act tool, and an emergency-stop control, each in its own module with
accurate readOnly/destructive annotations (ADR-0006).
"""

from __future__ import annotations

from praxis.tools import actuate, collect, drift, emergency, state
from praxis.tools.registry import ToolRegistry, ToolSpec

# The full set of registered tool names, asserted by the smoke test.
REGISTERED_TOOLS = (
    "query_facts",
    "fact_history",
    "ingest_observation",
    "drift_scan",
    "run_action",
    "emergency_stop",
)


def register_all(registry: ToolRegistry) -> None:
    """Register every tool. Read tools first, then the act and control tools."""
    state.register(registry)
    collect.register(registry)
    drift.register(registry)
    actuate.register(registry)
    emergency.register(registry)


__all__ = ["REGISTERED_TOOLS", "ToolRegistry", "ToolSpec", "register_all"]
