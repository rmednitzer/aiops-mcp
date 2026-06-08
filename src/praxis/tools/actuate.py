"""Actuation tool: the one destructive surface, fully tier-gated and trifecta-gated.

It builds the adapter request, classifies it, enforces the trifecta gate (SEC-4),
then routes through the adapter (host_type gate, SEC-5) and the executor
(DRY_RUN -> approve -> execute, SEC-6). It returns the outcome and the output hash,
never the output body in the audit (SEC-9).
"""

from __future__ import annotations

import json
from typing import Literal, get_args

from pydantic import Field

from praxis.actuation import (
    AnsibleAdapter,
    OpenTofuAdapter,
    RunbookAdapter,
    SSHAdapter,
    TalosctlAdapter,
)
from praxis.actuation.base import ActuationAdapter, HostInfo
from praxis.context import ServerContext, TrifectaViolation
from praxis.execution.contract import Approval, ApprovalError
from praxis.execution.patterns import Tier
from praxis.execution.runner import expected_token
from praxis.model.facts import HostType
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec

_ADAPTERS: dict[str, ActuationAdapter] = {
    "ssh": SSHAdapter(),
    "ansible": AnsibleAdapter(),
    "opentofu": OpenTofuAdapter(),
    "talosctl": TalosctlAdapter(),
    "runbook": RunbookAdapter(),
}

AdapterName = Literal["ansible", "opentofu", "runbook", "ssh", "talosctl"]
# The Literal is the advertised enum; keep it in lockstep with the adapter table so a
# new adapter cannot be reachable without appearing in the schema. Enforced at import
# (a raise, not an assert, so it holds under `python -O`).
if set(get_args(AdapterName)) != set(_ADAPTERS):  # pragma: no cover - import-time invariant
    raise RuntimeError("AdapterName Literal must match the _ADAPTERS table")


class RunActionArgs(ToolArgs):
    adapter: AdapterName
    host: str = Field(min_length=1)
    host_type: HostType
    action: str = Field(min_length=1)
    ssh_alias: str | None = None
    nodes: tuple[str, ...] = ()
    endpoints: tuple[str, ...] = ()
    dry_run: bool = True
    approval_token: str | None = None


def _run_action(args: RunActionArgs, ctx: ServerContext) -> str:
    adapter = _ADAPTERS[args.adapter]
    host = HostInfo(
        name=args.host,
        host_type=args.host_type,
        ssh_alias=args.ssh_alias,
        nodes=args.nodes,
        endpoints=args.endpoints,
    )
    token = args.approval_token

    request = adapter.build_request(host, args.action, dry_run=args.dry_run)
    decision = ctx.execution.policy.check(
        request.tool, request.command, base_tier=request.base_tier
    )
    approval = Approval(action_id=request.action_id(), token=token) if token is not None else None

    # Trifecta containment (SEC-4) applies to a real run only: a DRY_RUN is a
    # non-executing preview, and it is the step that yields the approval token.
    if not args.dry_run:
        approved = approval is not None
        if ctx.untrusted_ingested and decision.tier < Tier.T2:
            # Sub-T2 actions are not approval-gated by the executor, so the trifecta
            # gate validates and consumes the approval itself. Token presence alone
            # never satisfies the human gate: a caller-supplied, unvalidated string
            # cannot stand in for a confirmation (closes the bypass).
            approved = False
            if approval is not None:
                try:
                    ctx.execution.approvals.consume(
                        approval,
                        expected_action_id=request.action_id(),
                        expected_token=expected_token(request, decision.tier),
                    )
                    approved = True
                except ApprovalError as exc:
                    reason = f"trifecta containment: {exc}"
                    ctx.audit_trifecta_denial(
                        tool=request.tool, target=host.name, tier=decision.tier, reason=reason
                    )
                    raise TrifectaViolation(reason) from exc
        ctx.guard_actuation(
            tier=decision.tier, approved=approved, tool=request.tool, target=host.name
        )

    result = adapter.actuate(
        host, args.action, context=ctx.execution, dry_run=args.dry_run, approval=approval
    )
    body: dict[str, object] = {
        "ok": result.ok,
        "tier": result.decision.tier.label,
        "error": result.error,
        "output_sha256": result.output_sha256,
        "output_len": result.output_len,
        "output": result.output,
    }
    if args.dry_run:
        # Surface exactly what the operator must supply to approve the real run, so
        # the DRY_RUN -> approve -> execute flow is operable over MCP (SEC-6).
        body["action_id"] = request.action_id()
        body["approval_token"] = expected_token(request, decision.tier)
    return json.dumps(body, sort_keys=True)


def register(registry: ToolRegistry) -> None:
    registry.register(
        tool_spec(
            name="run_action",
            description="Run a tier-gated actuation via an adapter (DRY_RUN, approve, execute).",
            read_only=False,
            destructive=True,
            args_model=RunActionArgs,
            handler=_run_action,
        )
    )
