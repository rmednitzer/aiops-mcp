"""Tier classification and the deny-first policy gate (ADR-0004; SEC-1, SEC-3).

``classify`` is conservative: the declared base tier is a floor and command
content can only round the tier up, never down. ``Policy.check`` evaluates the
global deny list first and unconditionally, then mode gating, then the tier gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from praxis.execution.patterns import (
    PATTERNS_VERSION,
    Tier,
    command_tier,
    deny_match,
)


class Mode(Enum):
    """Server-wide ceiling on which tiers may run (ADR-0004)."""

    OPEN = "open"  # all tiers, each subject to its own gate
    GUARDED = "guarded"  # T0-T2; T3 refused
    READONLY = "readonly"  # T0 only


def _probe(tool: str, command: str | None) -> str:
    """The classification probe: the tool name plus the command string (BL-019).

    Including the tool name means a destructive cue carried in the tool name
    itself cannot dodge the patterns. Anything beyond these two strings (stdin,
    environment, file payloads) is not a classified channel; see the scope note
    in ``patterns.py``.
    """
    return f"{tool} {command}" if command else tool


def classify(tool: str, command: str | None = None, *, base_tier: Tier = Tier.T0) -> Tier:
    """Classify a call. The base tier is a floor; the command can only round up.

    A read collector declares ``base_tier=Tier.T0``; an act tool declares at least
    ``Tier.T1``. Probe content (sudo, rm -rf, tofu apply, ...) rounds the result
    up but never below the declared base. Ambiguity rounds up (SEC-3).
    """
    tier = base_tier
    probe = _probe(tool, command)
    if probe:
        tier = max(tier, command_tier(probe))
    return tier


@dataclass(frozen=True)
class Decision:
    """The outcome of a policy check, carried into the audit record."""

    allowed: bool
    tier: Tier
    reason: str
    requires_approval: bool
    denied: bool  # True only when the global deny list matched
    patterns_version: int = PATTERNS_VERSION


class Policy:
    """The single policy gate. Deny-first, then mode, then tier (SEC-1)."""

    def __init__(self, mode: Mode = Mode.GUARDED) -> None:
        self.mode = mode

    def check(
        self,
        tool: str,
        command: str | None = None,
        *,
        base_tier: Tier = Tier.T0,
    ) -> Decision:
        # 1. Deny list: global, unconditional, evaluated before any tier or mode
        #    gate, and applied in every mode including OPEN (SEC-1). The probe
        #    includes the tool name (BL-019).
        probe = _probe(tool, command)
        if probe:
            denied_by = deny_match(probe)
            if denied_by is not None:
                return Decision(
                    allowed=False,
                    tier=Tier.T3,
                    reason=f"denied by global deny list: {denied_by.pattern}",
                    requires_approval=False,
                    denied=True,
                )

        tier = classify(tool, command, base_tier=base_tier)

        # 2. Mode gate.
        if self.mode is Mode.READONLY and tier > Tier.T0:
            return Decision(
                allowed=False,
                tier=tier,
                reason=f"mode=readonly refuses {tier.label}",
                requires_approval=False,
                denied=False,
            )
        if self.mode is Mode.GUARDED and tier >= Tier.T3:
            return Decision(
                allowed=False,
                tier=tier,
                reason="mode=guarded refuses T3 (irreversible)",
                requires_approval=False,
                denied=False,
            )

        # 3. Tier gate: T2 and above require human approval (enforced by the
        #    runner's approval flow; the decision only reports the requirement).
        requires_approval = tier >= Tier.T2
        return Decision(
            allowed=True,
            tier=tier,
            reason=f"allowed at {tier.label} (mode={self.mode.value})",
            requires_approval=requires_approval,
            denied=False,
        )
