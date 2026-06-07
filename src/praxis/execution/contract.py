"""Execution contracts: predicates, budgets, approvals, and retry (ADR-0005).

These are the building blocks the runner composes around the execute step:

- Predicates with HARD/SOFT severity (a HARD precondition aborts; a SOFT one warns).
- A budget tracker that rejects non-finite and negative inputs at construction and
  at charge time, so a NaN/inf limit can never silently disable a ceiling.
- Single-use approvals bound to one action, so a T2+ approval cannot be replayed
  and a retry needs a fresh approval (SEC-2).
- A bounded retry policy (at most once by default).
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    HARD = "hard"  # failure aborts the call before execution
    SOFT = "soft"  # failure is recorded as a warning; execution proceeds


@dataclass(frozen=True)
class Predicate[T]:
    """A named, severity-tagged predicate over a subject of type ``T``."""

    name: str
    test: Callable[[T], bool]
    severity: Severity
    message: str


@dataclass(frozen=True)
class Violation:
    name: str
    severity: Severity
    message: str


@dataclass
class Contract[T]:
    """Preconditions, invariants, and postconditions over a subject of type ``T``."""

    preconditions: list[Predicate[T]] = field(default_factory=list)
    invariants: list[Predicate[T]] = field(default_factory=list)
    postconditions: list[Predicate[T]] = field(default_factory=list)

    @staticmethod
    def _eval(predicates: list[Predicate[T]], subject: T) -> list[Violation]:
        violations: list[Violation] = []
        for pred in predicates:
            try:
                ok = pred.test(subject)
            except Exception:  # noqa: BLE001 - a throwing predicate is a HARD failure
                violations.append(
                    Violation(pred.name, Severity.HARD, f"{pred.message} (predicate raised)")
                )
                continue
            if not ok:
                violations.append(Violation(pred.name, pred.severity, pred.message))
        return violations

    def check_pre(self, subject: T) -> list[Violation]:
        return self._eval(self.preconditions + self.invariants, subject)

    def check_post(self, subject: T) -> list[Violation]:
        return self._eval(self.invariants + self.postconditions, subject)

    @staticmethod
    def hard_failures(violations: list[Violation]) -> list[Violation]:
        return [v for v in violations if v.severity is Severity.HARD]


class BudgetError(Exception):
    """Raised when a budget is misconfigured or exceeded."""


def _finite_nonneg(value: float, name: str) -> float:
    if not math.isfinite(value):
        raise BudgetError(f"{name} must be finite, got {value!r}")
    if value < 0:
        raise BudgetError(f"{name} must be non-negative, got {value!r}")
    return value


class BudgetTracker:
    """Tracks cumulative cost against optional ceilings.

    ``None`` means unlimited for that axis. Non-finite or negative limits and
    charges are rejected, so a caller-fed NaN/inf can never disable a ceiling.
    """

    def __init__(
        self,
        *,
        max_actions: int | None = None,
        max_usd: float | None = None,
        max_wall_seconds: float | None = None,
    ) -> None:
        if max_actions is not None:
            if max_actions < 0:
                raise BudgetError(f"max_actions must be non-negative, got {max_actions!r}")
        if max_usd is not None:
            _finite_nonneg(max_usd, "max_usd")
        if max_wall_seconds is not None:
            _finite_nonneg(max_wall_seconds, "max_wall_seconds")
        self.max_actions = max_actions
        self.max_usd = max_usd
        self.max_wall_seconds = max_wall_seconds
        self.actions = 0
        self.usd = 0.0
        self.wall_seconds = 0.0

    def charge(self, *, actions: int = 1, usd: float = 0.0, wall_seconds: float = 0.0) -> None:
        if actions < 0:
            raise BudgetError(f"actions charge must be non-negative, got {actions!r}")
        _finite_nonneg(usd, "usd charge")
        _finite_nonneg(wall_seconds, "wall_seconds charge")
        new_actions = self.actions + actions
        new_usd = self.usd + usd
        new_wall = self.wall_seconds + wall_seconds
        if self.max_actions is not None and new_actions > self.max_actions:
            raise BudgetError(f"action budget exceeded: {new_actions} > {self.max_actions}")
        if self.max_usd is not None and new_usd > self.max_usd:
            raise BudgetError(f"usd budget exceeded: {new_usd} > {self.max_usd}")
        if self.max_wall_seconds is not None and new_wall > self.max_wall_seconds:
            raise BudgetError(f"wall budget exceeded: {new_wall} > {self.max_wall_seconds}")
        self.actions, self.usd, self.wall_seconds = new_actions, new_usd, new_wall


class ApprovalError(Exception):
    """Raised when an approval is missing, mismatched, or already consumed."""


@dataclass(frozen=True)
class Approval:
    """A human approval bound to exactly one action."""

    action_id: str
    token: str


class ApprovalRegistry:
    """Tracks consumed approvals so each is single-use (SEC-2)."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def consume(self, approval: Approval, *, expected_action_id: str, expected_token: str) -> None:
        if approval.action_id != expected_action_id:
            raise ApprovalError("approval is not bound to this action")
        if approval.token != expected_token:
            raise ApprovalError("approval token does not match the required confirmation")
        key = f"{approval.action_id}:{approval.token}"
        if key in self._consumed:
            raise ApprovalError("approval already used; a retry requires a fresh approval")
        self._consumed.add(key)


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry. ``max_retries`` defaults to one and must be a non-negative int."""

    max_retries: int = 1

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise BudgetError(f"max_retries must be non-negative, got {self.max_retries!r}")
