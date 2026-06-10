"""Emergency stop: the operator-facing actuator for the kill switch (BL-075; SEC-8).

Tripping the switch halts every subsequent execution at the first step of the
audited path. It runs through ``run()`` at T0 so the trip itself is audited, yet is
never blocked by the approval gate, the trifecta latch, or the action budget: the
emergency stop must always be reachable, including in a tainted or budget-exhausted
session. With ``PRAXIS_KILL_SWITCH_PATH`` configured the trip is durable across a
restart; restoring service is a deliberate out-of-band operator action (reset the
in-process switch and remove the sentinel file), never a tool call.
"""

from __future__ import annotations

import json

from pydantic import Field

from praxis.context import ServerContext
from praxis.tools._audited import run_audited
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec


class EmergencyStopArgs(ToolArgs):
    reason: str = Field(
        min_length=1,
        max_length=500,
        description="Why execution is being halted; recorded in the audit trail.",
    )


def _emergency_stop(args: EmergencyStopArgs, ctx: ServerContext) -> str:
    def execute() -> str:
        ctx.execution.kill_switch.trip(reason=args.reason)
        return json.dumps({"stopped": True, "reason": args.reason}, sort_keys=True)

    return run_audited(
        ctx,
        tool="emergency_stop",
        args={"reason": args.reason},
        execute=execute,
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        tool_spec(
            name="emergency_stop",
            description=(
                "Trip the kill switch to halt all subsequent execution immediately "
                "(SEC-8). Restoring service is an out-of-band operator action."
            ),
            # Changes server state (it is not a read), but it is protective, not
            # destructive: it stops actuation rather than performing any.
            read_only=False,
            destructive=False,
            args_model=EmergencyStopArgs,
            handler=_emergency_stop,
        )
    )
