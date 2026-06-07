"""The single audited execution path (ADR-0005; invariant 1, SEC-2).

``run`` is the one entry point through which every read tool and every act tool
passes. Its pipeline is fixed and total:

    kill switch -> classify -> policy (deny-first) -> redact audited args ->
    approval/HITL gate (T2+) -> contract preconditions -> execute ->
    bounded error formatting -> hash + length -> truncate preview -> audit record

Every call writes exactly one audit record, including denials and errors. Output
bodies are never stored: the audit keeps the SHA-256 and the length of the full
output (proof), while only a truncated preview is returned to the caller.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from praxis.execution.audit import EMPTY_SHA256, AuditLogger, AuditRecord, sha256_text
from praxis.execution.contract import (
    Approval,
    ApprovalError,
    ApprovalRegistry,
    Contract,
)
from praxis.execution.patterns import PATTERNS_VERSION, Tier
from praxis.execution.policy import Decision, Policy
from praxis.execution.redaction import redact, redact_args

_MULTI_TARGET = set(",; \t\n")


@dataclass
class KillSwitch:
    """An immediate, operator-cleared global stop (SEC-8)."""

    _tripped: bool = False

    def trip(self) -> None:
        self._tripped = True

    def reset(self) -> None:
        """Clear the kill switch. Only an explicit operator action calls this."""
        self._tripped = False

    def is_tripped(self) -> bool:
        return self._tripped


@dataclass(frozen=True)
class ExecutionRequest:
    """A request to run one tool through the audited path."""

    tool: str
    command: str | None = None
    args: Mapping[str, object] = field(default_factory=dict)
    target: str | None = None
    base_tier: Tier = Tier.T0
    dry_run: bool = False
    approval: Approval | None = None
    # Marks a call as carrying attacker-influenced content (collected host data,
    # command output, a feed). Used by the trifecta containment gate (SEC-4).
    untrusted: bool = False

    def action_id(self) -> str:
        canonical = json.dumps(
            {
                "tool": self.tool,
                "command": self.command,
                "target": self.target,
                "args": self.args,
            },
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )
        return sha256_text(canonical)[:16]


@dataclass(frozen=True)
class ExecutionResult:
    """The outcome of a run. ``output`` is a truncated preview, never the audit body."""

    ok: bool
    decision: Decision
    output: str
    output_sha256: str
    output_len: int
    error: str | None
    record: AuditRecord


@dataclass
class ExecutionContext:
    """Everything the runner needs, assembled once per server (ADR-0005, ADR-0006)."""

    policy: Policy
    audit: AuditLogger
    kill_switch: KillSwitch = field(default_factory=KillSwitch)
    approvals: ApprovalRegistry = field(default_factory=ApprovalRegistry)
    contract: Contract[ExecutionRequest] = field(default_factory=Contract)
    max_output_bytes: int = 65536


def expected_token(request: ExecutionRequest, tier: Tier) -> str:
    """The confirmation token the operator must supply for a gated action.

    T3 tokens are target-bound and typed (they cannot be reused for a different
    target); T2 tokens are bound to the action id.
    """
    if tier >= Tier.T3:
        return f"CONFIRM-{request.target}"
    return f"APPROVE-{request.action_id()}"


def _is_multi_target(target: str | None) -> bool:
    if target is None:
        return True
    return any(ch in _MULTI_TARGET for ch in target.strip()) or not target.strip()


def _bounded_error(exc: Exception) -> str:
    """A bounded, secret-free error string. Never a raw traceback (invariant 1).

    The stringify is itself contained: a hostile or broken ``__str__`` on the
    raised exception must not escape the audited path and become an unbounded
    raise out of ``run`` (BL-044).
    """
    try:
        detail = redact(str(exc))
    except Exception:  # noqa: BLE001 - a broken __str__ must not break run()
        detail = "<unprintable>"
    return f"{type(exc).__name__}: {detail}"[:500]


def _truncate(text: str, limit_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="surrogatepass")
    if len(encoded) <= limit_bytes:
        return text
    clipped = encoded[:limit_bytes].decode("utf-8", errors="ignore")
    return clipped + f"\n[... truncated, {len(encoded)} bytes total]"


def run(
    request: ExecutionRequest,
    execute: Callable[[], str],
    *,
    context: ExecutionContext,
) -> ExecutionResult:
    """Run one tool through the single audited path. Never raises from execution."""
    redacted = redact_args(dict(request.args))

    def audit(
        decision_label: str,
        tier_label: str,
        *,
        output_sha256: str = EMPTY_SHA256,
        output_len: int = 0,
        error: str | None = None,
    ) -> AuditRecord:
        return context.audit.record(
            tool=request.tool,
            target=request.target,
            tier=tier_label,
            decision=decision_label,
            args=redacted,
            output_sha256=output_sha256,
            output_len=output_len,
            error=error,
            patterns_version=PATTERNS_VERSION,
        )

    def denied(decision: Decision, reason: str) -> ExecutionResult:
        record = audit("denied", decision.tier.label, error=reason)
        return ExecutionResult(
            ok=False,
            decision=decision,
            output="",
            output_sha256=EMPTY_SHA256,
            output_len=0,
            error=reason,
            record=record,
        )

    # 0. Kill switch: checked on every call, before anything else (SEC-8).
    if context.kill_switch.is_tripped():
        reason = "kill switch engaged; execution disabled"
        return denied(
            Decision(
                allowed=False,
                tier=Tier.T0,
                reason=reason,
                requires_approval=False,
                denied=True,
            ),
            reason,
        )

    # 1. Classify + policy (deny-first, unconditional) (SEC-1, SEC-3).
    decision = context.policy.check(request.tool, request.command, base_tier=request.base_tier)
    if not decision.allowed:
        return denied(decision, decision.reason)

    # 2. Approval / HITL gate for T2+ real runs. A DRY_RUN is a preview and needs
    #    no approval; the approval flow is DRY_RUN -> approve -> execute (SEC-2, SEC-6).
    if decision.requires_approval and not request.dry_run:
        if decision.tier >= Tier.T3 and _is_multi_target(request.target):
            return denied(decision, "T3 is irreversible: supply exactly one target")
        if request.approval is None:
            return denied(
                decision,
                "approval required at T2+: run with dry_run=True, then approve",
            )
        try:
            context.approvals.consume(
                request.approval,
                expected_action_id=request.action_id(),
                expected_token=expected_token(request, decision.tier),
            )
        except ApprovalError as exc:
            return denied(decision, str(exc))

    # 3. Contract preconditions and invariants. A HARD failure aborts (SEC-2).
    violations = context.contract.check_pre(request)
    hard = Contract.hard_failures(violations)
    if hard:
        reason = "; ".join(f"{v.name}: {v.message}" for v in hard)
        return denied(decision, f"precondition failed: {reason}")

    # 4. Execute. Any exception becomes a bounded error; never a raw traceback,
    #    never re-raised out of the audited path (invariant 1).
    error: str | None = None
    output = ""
    try:
        output = execute()
    except Exception as exc:  # noqa: BLE001 - bounded and audited, by design
        error = _bounded_error(exc)
        output = ""

    # 5. Hash + length over the FULL output (tamper-evidence proof), then keep only
    #    a truncated preview for the caller. The body is never stored (SEC-9).
    output_sha256 = sha256_text(output)
    output_len = len(output.encode("utf-8", errors="surrogatepass"))
    preview = _truncate(output, context.max_output_bytes)

    decision_label = "error" if error is not None else "allowed"
    record = audit(
        decision_label,
        decision.tier.label,
        output_sha256=output_sha256,
        output_len=output_len,
        error=error,
    )
    return ExecutionResult(
        ok=error is None,
        decision=decision,
        output=preview,
        output_sha256=output_sha256,
        output_len=output_len,
        error=error,
        record=record,
    )
