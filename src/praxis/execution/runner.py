"""The single audited execution path (ADR-0005, ADR-0016; invariant 1, SEC-2).

``run`` is the one entry point through which every read tool and every act tool
passes. Its pipeline is fixed and total:

    redact audited args (contained) -> kill switch -> classify ->
    policy (deny-first) -> untrusted-latch arm -> approval/HITL + trifecta gate ->
    contract preconditions -> budget -> execute ->
    bounded error formatting -> hash + length -> truncate preview -> audit record

Redaction runs first because every audit record, including the kill-switch denial
itself, is built from the redacted args; it is contained (BL-077), so a redaction
failure can never delay or mask the kill switch.

Every call writes exactly one audit record, including denials and errors. Output
bodies are never stored: the audit keeps the SHA-256 and the length of the full
output (proof), while only a truncated preview is returned to the caller.

Approvals (BL-072, ADR-0016): a gated DRY_RUN mints a server-generated, single-use,
TTL-bound nonce and surfaces it OUT-OF-BAND via ``ExecutionContext.approval_sink``
(default: the server's stderr, the operator console). The nonce never appears in a
tool result or in the audit log, so a caller that only sees the MCP channel cannot
self-approve.

Trifecta containment (BL-083, ADR-0016; SEC-4, invariant 8): once the session
taint latch is armed (any ingest of attacker-influenced content, or a read that
returned observed facts), every T1+ real run requires a minted approval, enforced
here in the single path rather than per-handler.
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from praxis.execution.audit import EMPTY_SHA256, AuditLogger, AuditRecord, sha256_text
from praxis.execution.contract import (
    Approval,
    ApprovalError,
    ApprovalRegistry,
    BudgetError,
    BudgetTracker,
    Contract,
)
from praxis.execution.correlation import current_client_id, current_request_id
from praxis.execution.patterns import PATTERNS_VERSION, Tier
from praxis.execution.policy import Decision, Policy
from praxis.execution.redaction import redact, redact_args

_MULTI_TARGET = set(",; \t\n")


@dataclass
class KillSwitch:
    """An immediate, operator-cleared global stop (SEC-8; BL-075, ADR-0016).

    With a ``sentinel_path`` configured, a trip also writes a sentinel file so the
    stop survives a restart, and the switch reads as tripped whenever the sentinel
    exists (an operator can engage it out-of-band with ``touch``). ``reset`` clears
    only the in-memory trip; removing the sentinel is a deliberate out-of-band
    operator action. If the sentinel cannot be read, the switch fails closed.
    """

    sentinel_path: Path | None = None
    _tripped: bool = False

    def trip(self, reason: str = "operator") -> None:
        # The in-memory trip ALWAYS succeeds first: the emergency stop must never
        # be blocked by a failing filesystem. A failed sentinel write only costs
        # durability across restart, so it is warned about, never raised.
        self._tripped = True
        if self.sentinel_path is not None:
            try:
                stamp = datetime.now(UTC).isoformat(timespec="seconds")
                self.sentinel_path.write_text(f"{stamp} {reason}\n", encoding="utf-8")
            except Exception as exc:  # noqa: BLE001 - durability loss, not stop failure
                with suppress(Exception):
                    print(
                        f"[praxis.killswitch] sentinel write failed ({exc!r}); the stop "
                        "is in-memory only and will NOT survive a restart",
                        file=sys.stderr,
                    )

    def reset(self) -> None:
        """Clear the in-memory trip. Only an explicit operator action calls this.

        A configured sentinel file is NOT removed here: restoring a durable stop
        requires the operator to delete the sentinel out-of-band.
        """
        self._tripped = False

    def is_tripped(self) -> bool:
        if self._tripped:
            return True
        if self.sentinel_path is None:
            return False
        try:
            return self.sentinel_path.exists()
        except OSError:
            return True  # the stop channel is unreadable: fail closed (SEC-8)


@dataclass
class SessionTaint:
    """Latches once the session has taken in attacker-influenced content (SEC-4).

    Shared between the server context and the execution context so the trifecta
    gate inside ``run`` and the tools that ingest or read observed data act on one
    state (BL-083). The latch never clears within a session.
    """

    untrusted_ingested: bool = False

    def mark(self) -> None:
        self.untrusted_ingested = True


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
    # command output, a feed). ``run`` arms the session taint latch for such a
    # call before executing it (SEC-4; BL-083).
    untrusted: bool = False
    # The canonical identity of the action for approval binding, when it differs
    # from ``command``. A native-dry-run adapter previews with a different argv
    # (ansible --check, tofu plan) than it executes; the approval minted by the
    # preview must bind to the REAL command, so adapters set this to the real-run
    # command string (BL-072, ADR-0016). None means ``command`` is the identity.
    action_key: str | None = None

    def action_id(self) -> str:
        canonical = json.dumps(
            {
                "tool": self.tool,
                "command": self.action_key if self.action_key is not None else self.command,
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
    # Optional per-session ceilings, enforced on the audited path (BL-074).
    budget: BudgetTracker | None = None
    # The session untrusted-content latch (SEC-4; BL-083).
    taint: SessionTaint = field(default_factory=SessionTaint)
    # Where minted approval nonces are surfaced to the operator, OUT-OF-BAND from
    # the MCP channel (BL-072). None means the server's stderr.
    approval_sink: Callable[[str], None] | None = None
    # Per-session consent ceiling (BL-045, ADR-0006 Decision 4; ADR-0041): the maximum
    # tier this session may engage, recorded per client by the multi-client transport.
    # None (the stdio default) imposes no ceiling beyond the server mode; a value denies
    # any action classified above it, enforced in-path (step 3a of run).
    consent_ceiling: Tier | None = None


def _is_multi_target(target: str | None) -> bool:
    if target is None:
        return True
    return any(ch in _MULTI_TARGET for ch in target.strip()) or not target.strip()


def bounded_error(exc: Exception) -> str:
    """A bounded, secret-free error string. Never a raw traceback (invariant 1).

    Shared by the audited path and the stdio server's tool-error path so both
    contain an exception identically. The stringify is itself contained: a
    hostile or broken ``__str__`` on the raised exception must not escape and
    become an unbounded raise (BL-044).
    """
    try:
        detail = redact(str(exc))
    except Exception:  # noqa: BLE001 - a broken __str__ must not break the caller
        detail = "<unprintable>"
    return f"{type(exc).__name__}: {detail}"[:500]


def _truncate(text: str, limit_bytes: int) -> str:
    encoded = text.encode("utf-8", errors="surrogatepass")
    if len(encoded) <= limit_bytes:
        return text
    clipped = encoded[:limit_bytes].decode("utf-8", errors="ignore")
    return clipped + f"\n[... truncated, {len(encoded)} bytes total]"


def _surface_approval(
    context: ExecutionContext,
    *,
    tool: str,
    action_id: str,
    target: str | None,
    tier: Tier,
    token: str,
) -> None:
    """Hand a minted nonce to the operator, never to the MCP caller (BL-072).

    Failures are contained: a broken sink degrades to stderr, and a broken stderr
    loses the token (the action then simply cannot be approved: fail closed).
    """
    message = (
        f"praxis approval minted: tool={tool} action_id={action_id} "
        f"target={target} tier={tier.label} token={token} "
        f"ttl_s={int(context.approvals.ttl_seconds)} (single-use; "
        f"pass as approval_token with dry_run=false to execute)"
    )
    try:
        if context.approval_sink is not None:
            context.approval_sink(message)
        else:
            print(message, file=sys.stderr)
    except Exception:  # noqa: BLE001 - the sink must not break the audited path
        with suppress(Exception):
            print(message, file=sys.stderr)


def run(
    request: ExecutionRequest,
    execute: Callable[[], str],
    *,
    context: ExecutionContext,
) -> ExecutionResult:
    """Run one tool through the single audited path. Never raises from execution."""

    # 1. Redact the audited args first, contained: every later step (including
    #    denials) writes an audit record built from them. A redaction failure on a
    #    hostile args payload audits-and-denies instead of raising out of the
    #    audited path unaudited (BL-077).
    redaction_failed = False
    try:
        redacted = redact_args(dict(request.args))
    except Exception:  # noqa: BLE001 - contained: deny with placeholder args
        redacted = {"_redaction": "failed; args withheld"}
        redaction_failed = True

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
            request_id=current_request_id(),
            client_id=current_client_id(),
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

    def refusal(reason: str) -> Decision:
        return Decision(
            allowed=False,
            tier=Tier.T0,
            reason=reason,
            requires_approval=False,
            denied=True,
        )

    # 2. Kill switch: checked on every call, before any decision or execution
    #    (SEC-8). Only the contained arg redaction above runs earlier, because
    #    this denial's own audit record is built from the redacted args.
    if context.kill_switch.is_tripped():
        reason = "kill switch engaged; execution disabled"
        return denied(refusal(reason), reason)

    if redaction_failed:
        reason = "argument redaction failed; call refused (BL-077)"
        return denied(refusal(reason), reason)

    # 3. Classify + policy (deny-first, unconditional) (SEC-1, SEC-3).
    decision = context.policy.check(request.tool, request.command, base_tier=request.base_tier)
    if not decision.allowed:
        return denied(decision, decision.reason)

    # 3a. Per-session consent ceiling (BL-045, ADR-0006 Decision 4; ADR-0041). A
    #     multi-client session may be held to a tier ceiling at or below the server
    #     mode; an action classified above its recorded consent is denied here, in-path
    #     and audited. None (the stdio default) imposes no ceiling beyond the mode.
    if context.consent_ceiling is not None and decision.tier > context.consent_ceiling:
        reason = (
            f"action tier {decision.tier.label} exceeds this session's consented ceiling "
            f"{context.consent_ceiling.label}"
        )
        return denied(decision, reason)

    # 4. Arm the session taint latch for a call that carries attacker-influenced
    #    content, BEFORE the gate is evaluated, so the very first untrusted call
    #    is gated by its own taint: conservative, fail-closed (SEC-4; BL-083).
    if request.untrusted:
        context.taint.mark()

    # 5. Approval / HITL gate. T2+ always gates a real run; once the session
    #    taint latch is armed, any T1+ real run gates too (SEC-2, SEC-4, SEC-6;
    #    invariant 8). A DRY_RUN is a preview and needs no approval: instead, a
    #    gated DRY_RUN mints the single-use nonce for the matching real run.
    trifecta_gated = context.taint.untrusted_ingested and decision.tier >= Tier.T1
    gate_required = decision.requires_approval or trifecta_gated
    multi_target_t3 = decision.tier >= Tier.T3 and _is_multi_target(request.target)
    if gate_required and not request.dry_run:
        if multi_target_t3:
            return denied(decision, "T3 is irreversible: supply exactly one target")
        if request.approval is None:
            if decision.requires_approval:
                reason = "approval required at T2+: run with dry_run=True, then approve"
            else:
                reason = (
                    "untrusted content ingested this session; actuation requires "
                    "an approval (SEC-4): run with dry_run=True, then approve"
                )
            return denied(decision, reason)
        try:
            context.approvals.consume(
                request.approval,
                action_id=request.action_id(),
                target=request.target,
                tier=decision.tier,
                patterns_version=decision.patterns_version,
            )
        except ApprovalError as exc:
            return denied(decision, str(exc))

    # 6. Contract preconditions and invariants. A HARD failure aborts (SEC-2).
    violations = context.contract.check_pre(request)
    hard = Contract.hard_failures(violations)
    if hard:
        reason = "; ".join(f"{v.name}: {v.message}" for v in hard)
        return denied(decision, f"precondition failed: {reason}")

    # 7. Budget: a T1+ real run that has passed every gate charges one action just
    #    before executing, so a denied or mis-approved call never burns the ceiling
    #    (a refused approval must not be able to exhaust the budget and lock the
    #    operator out), while every executed action is counted (BL-074). T0 reads
    #    and the emergency stop are not actions. Wall time is recorded after
    #    execution and checked at the next charge.
    if context.budget is not None and decision.tier >= Tier.T1 and not request.dry_run:
        try:
            context.budget.charge(actions=1)
        except BudgetError as exc:
            return denied(decision, f"budget exceeded: {exc}")

    # 8. Execute. Any exception becomes a bounded error; never a raw traceback,
    #    never re-raised out of the audited path (invariant 1).
    error: str | None = None
    output = ""
    started = time.monotonic()
    try:
        output = execute()
    except Exception as exc:  # noqa: BLE001 - bounded and audited, by design
        error = bounded_error(exc)
        output = ""
    if context.budget is not None:
        context.budget.record_spend(wall_seconds=max(0.0, time.monotonic() - started))

    # 9. A successful gated DRY_RUN mints the out-of-band approval nonce for the
    #    matching real run (BL-072). Never minted for a T3 multi-target request
    #    (the real run would be refused) and never echoed in the result.
    if request.dry_run and gate_required and error is None and not multi_target_t3:
        token = context.approvals.mint(
            action_id=request.action_id(),
            target=request.target,
            tier=decision.tier,
            patterns_version=decision.patterns_version,
        )
        _surface_approval(
            context,
            tool=request.tool,
            action_id=request.action_id(),
            target=request.target,
            tier=decision.tier,
            token=token,
        )

    # 10. Hash + length over the FULL output (tamper-evidence proof), then keep only
    #    a truncated preview for the caller. The body is never stored (SEC-9).
    #    Encoded once: reads can route multi-megabyte bodies through here.
    encoded = output.encode("utf-8", errors="surrogatepass")
    output_sha256 = hashlib.sha256(encoded).hexdigest()
    output_len = len(encoded)
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
