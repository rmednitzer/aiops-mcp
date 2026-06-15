"""Actuation tool: the one destructive surface, fully tier-gated and trifecta-gated.

It builds the adapter request and routes through the adapter (host_type gate,
SEC-5) into the single audited path, which enforces the approval flow
(DRY_RUN -> minted approval -> execute, SEC-2/SEC-6), the trifecta gate (SEC-4,
BL-083), and the optional credential-scope gate (BL-049). The approval token is
minted by the server and surfaced OUT-OF-BAND on the operator console, never in
this tool's response (BL-072, ADR-0016). The response carries the outcome and the
output hash, never the output body in the audit (SEC-9).
"""

from __future__ import annotations

import json
from dataclasses import replace
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
from praxis.config import CONFIG
from praxis.context import ServerContext
from praxis.execution.contract import Approval, Contract, Predicate, Severity
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionContext, ExecutionRequest
from praxis.model.facts import HostType
from praxis.tools.registry import ToolArgs, ToolRegistry, tool_spec

_ADAPTERS: dict[str, ActuationAdapter] = {
    "ssh": SSHAdapter(),
    "ansible": AnsibleAdapter(playbook_root=CONFIG.playbook_root),
    "opentofu": OpenTofuAdapter(tofu_root=CONFIG.tofu_root),
    "talosctl": TalosctlAdapter(),
    "runbook": RunbookAdapter(runbook_root=CONFIG.runbook_root),
}

AdapterName = Literal["ansible", "opentofu", "runbook", "ssh", "talosctl"]
HostTypeName = Literal["ubuntu", "talos", "windows", "cloud"]
# The Literals are the advertised enums; keep them in lockstep with their source of
# truth so a new adapter or host type cannot be reachable without appearing in the
# schema. Enforced at import (a raise, not an assert, so it holds under `python -O`).
if set(get_args(AdapterName)) != set(_ADAPTERS):  # pragma: no cover - import-time invariant
    raise RuntimeError("AdapterName Literal must match the _ADAPTERS table")
if set(get_args(HostTypeName)) != {h.value for h in HostType}:  # pragma: no cover
    raise RuntimeError("HostTypeName Literal must match HostType values")


class RunActionArgs(ToolArgs):
    adapter: AdapterName
    host: str = Field(min_length=1)
    # A Literal of the host_type values (strict-mode and JSON friendly); mapped to the
    # HostType enum in the handler.
    host_type: HostTypeName
    action: str = Field(min_length=1)
    ssh_alias: str | None = None
    # JSON arrays decode to lists; the handler converts to the tuples HostInfo holds.
    nodes: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    dry_run: bool = True
    approval_token: str | None = None
    # Structured wipe scope for `talosctl reset` (BL-025). Never implicit: omitting
    # it means the safe default (system-disk); `all` must be asked for by name.
    wipe_mode: Literal["system-disk", "user-disks", "all"] | None = None
    # Narrow the talosctl pre-upgrade health gate to client-side checks
    # (`talosctl health --server=false`, BL-102). Default False keeps the full
    # server-side check; set True only when a post-bootstrap cluster's server-side
    # checks spuriously block an upgrade. The gate still runs and still HARD-gates.
    health_client_side_only: bool = False
    # OpenTofu workspace selection (`tofu -chdir=<dir>`, BL-105). Confined to
    # PRAXIS_TOFU_ROOT; supplying it with no root configured is refused (fail closed).
    # None keeps tofu running in its default working directory.
    tofu_chdir: str | None = None


def _broker_gated_context(ctx: ServerContext, host: HostInfo) -> ExecutionContext:
    """Merge the credential-scope HARD precondition when grants exist (BL-049).

    With no broker, or a broker holding zero grants, scoped-credential enforcement
    is off (the single-operator default) and the execution context passes through
    unchanged. Once the operator issues a grant, every actuation must be covered
    by one, and an uncovered call is an audited refusal inside ``run()``.
    """
    broker = ctx.broker
    if broker is None or not broker.has_grants():
        return ctx.execution
    policy = ctx.execution.policy

    def covered(req: ExecutionRequest) -> bool:
        # The tier is classified lazily from the request the runner actually
        # gates, so this predicate can never disagree with the decision run()
        # enforces (one classification source, evaluated at check time).
        tier = policy.check(req.tool, req.command, base_tier=req.base_tier).tier
        return broker.authorized(host=host.name, tier=tier)

    pred = Predicate[ExecutionRequest](
        name="credential_scope",
        test=covered,
        severity=Severity.HARD,
        message=(
            f"no credential grant covers host {host.name!r} at the classified "
            "tier (scoped credentials, BL-049)"
        ),
    )
    merged = Contract[ExecutionRequest](
        preconditions=[*ctx.execution.contract.preconditions, pred],
        invariants=ctx.execution.contract.invariants,
        postconditions=ctx.execution.contract.postconditions,
    )
    return replace(ctx.execution, contract=merged)


def _run_action(args: RunActionArgs, ctx: ServerContext) -> str:
    adapter = _ADAPTERS[args.adapter]
    host = HostInfo(
        name=args.host,
        host_type=HostType(args.host_type),
        ssh_alias=args.ssh_alias,
        nodes=tuple(args.nodes),
        endpoints=tuple(args.endpoints),
    )
    params: dict[str, object] = {}
    if args.wipe_mode is not None:
        params["wipe_mode"] = args.wipe_mode
    if args.health_client_side_only:
        params["health_client_side_only"] = True
    if args.tofu_chdir is not None:
        params["chdir"] = args.tofu_chdir

    request = adapter.build_request(host, args.action, params, dry_run=args.dry_run)
    approval = (
        Approval(action_id=request.action_id(), token=args.approval_token)
        if args.approval_token is not None
        else None
    )

    result = adapter.actuate(
        host,
        args.action,
        params,
        context=_broker_gated_context(ctx, host),
        dry_run=args.dry_run,
        approval=approval,
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
        # The action id lets the operator bind their approval to this exact
        # request. The token itself is NEVER in this response: a gated dry run
        # mints it to the operator console, out-of-band (BL-072, ADR-0016).
        body["action_id"] = request.action_id()
        gated = result.decision.requires_approval or (
            ctx.untrusted_ingested and result.decision.tier >= Tier.T1
        )
        if result.ok and gated:
            body["approval"] = (
                "a single-use approval token was minted to the server operator "
                "console (out-of-band); pass it as approval_token with "
                "dry_run=false"
            )
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
