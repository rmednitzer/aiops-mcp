"""Actuation tool: the one destructive surface, fully tier-gated and trifecta-gated.

It builds the adapter request, classifies it, enforces the trifecta gate (SEC-4),
then routes through the adapter (host_type gate, SEC-5) and the executor
(DRY_RUN -> approve -> execute, SEC-6). It returns the outcome and the output hash,
never the output body in the audit (SEC-9).
"""

from __future__ import annotations

import json

from praxis.actuation import (
    AnsibleAdapter,
    OpenTofuAdapter,
    RunbookAdapter,
    SSHAdapter,
    TalosctlAdapter,
)
from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.context import ServerContext
from praxis.execution.contract import Approval
from praxis.model.facts import HostType
from praxis.tools.registry import ToolRegistry, ToolSpec

_ADAPTERS: dict[str, ActuationAdapter] = {
    "ssh": SSHAdapter(),
    "ansible": AnsibleAdapter(),
    "opentofu": OpenTofuAdapter(),
    "talosctl": TalosctlAdapter(),
    "runbook": RunbookAdapter(),
}

_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "adapter": {"type": "string", "enum": sorted(_ADAPTERS)},
        "host": {"type": "string"},
        "host_type": {"type": "string", "enum": [h.value for h in HostType]},
        "action": {"type": "string"},
        "ssh_alias": {"type": "string"},
        "nodes": {"type": "array", "items": {"type": "string"}},
        "endpoints": {"type": "array", "items": {"type": "string"}},
        "dry_run": {"type": "boolean", "default": True},
        "approval_token": {"type": "string"},
    },
    "required": ["adapter", "host", "host_type", "action"],
}


def _str_list(value: object) -> tuple[str, ...]:
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def _run_action(args: dict[str, object], ctx: ServerContext) -> str:
    adapter = _ADAPTERS.get(str(args.get("adapter", "")))
    if adapter is None:
        return json.dumps({"error": f"unknown adapter: {args.get('adapter')!r}"})
    try:
        host_type = HostType(str(args.get("host_type", "")))
    except ValueError:
        return json.dumps({"error": f"unknown host_type: {args.get('host_type')!r}"})

    alias = args.get("ssh_alias")
    host = HostInfo(
        name=str(args.get("host", "")),
        host_type=host_type,
        ssh_alias=alias if isinstance(alias, str) else None,
        nodes=_str_list(args.get("nodes")),
        endpoints=_str_list(args.get("endpoints")),
    )
    action = str(args.get("action", ""))
    dry_run = bool(args.get("dry_run", True))
    token = args.get("approval_token")

    request = adapter.build_request(host, action, dry_run=dry_run)
    decision = ctx.execution.policy.check(
        request.tool, request.command, base_tier=request.base_tier
    )
    approval = (
        Approval(action_id=request.action_id(), token=token) if isinstance(token, str) else None
    )

    # Trifecta containment (SEC-4): once untrusted content is in the session,
    # actuation needs the human gate even below T2.
    ctx.guard_actuation(tier=decision.tier, approved=approval is not None)

    result = adapter.actuate(
        host, action, context=ctx.execution, dry_run=dry_run, approval=approval
    )
    return json.dumps(
        {
            "ok": result.ok,
            "tier": result.decision.tier.label,
            "error": result.error,
            "output_sha256": result.output_sha256,
            "output_len": result.output_len,
            "output": result.output,
        },
        sort_keys=True,
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        ToolSpec(
            name="run_action",
            description="Run a tier-gated actuation via an adapter (DRY_RUN, approve, execute).",
            read_only=False,
            destructive=True,
            input_schema=_SCHEMA,
            handler=_run_action,
        )
    )
