"""Execution contracts: predicates, budgets, approvals, and retry (ADR-0005).

These are the building blocks the runner composes around the execute step:

- Predicates with HARD/SOFT severity (a HARD precondition aborts; a SOFT one warns).
- A budget tracker that rejects non-finite and negative inputs at construction and
  at charge time, so a NaN/inf limit can never silently disable a ceiling.
- Server-minted, single-use approval nonces bound to one action, target, tier, and
  patterns version, with a TTL, so a T2+ approval cannot be forged by the caller,
  replayed, or carried across a policy change (SEC-2; BL-072, ADR-0016). A restart
  clears all pending nonces: fail closed.
- A bounded retry policy (at most once by default).
"""

from __future__ import annotations

import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

from praxis.execution.patterns import Tier


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

    def record_spend(self, *, usd: float = 0.0, wall_seconds: float = 0.0) -> None:
        """Record spend that has already happened (post-execute accounting).

        Unlike ``charge``, this never raises on a ceiling: the work is done, so
        the honest move is to record the overspend, which makes the NEXT
        ``charge`` fail its ceiling check (BL-074).
        """
        self.usd += _finite_nonneg(usd, "usd charge")
        self.wall_seconds += _finite_nonneg(wall_seconds, "wall_seconds charge")


class ApprovalError(Exception):
    """Raised when an approval is missing, mismatched, or already consumed."""


@dataclass(frozen=True)
class Approval:
    """A human approval bound to exactly one action."""

    action_id: str
    token: str


@dataclass(frozen=True)
class _PendingApproval:
    """A minted nonce and the request facts it is bound to (BL-072)."""

    action_id: str
    target: str | None
    tier: Tier
    patterns_version: int
    expires_at: float  # monotonic deadline


class ApprovalRegistry:
    """Mints and consumes single-use approval nonces (SEC-2; BL-072, ADR-0016).

    The token is server-generated (``secrets.token_urlsafe``), never derivable from
    the request, surfaced to the operator out-of-band (never in a tool result), and
    bound to the action id, the target, the tier, and the ``PATTERNS_VERSION`` that
    classified the action. It expires after ``ttl_seconds`` and is single-use. The
    registry is in-memory only: a server restart invalidates every pending nonce
    (fail closed).
    """

    _MAX_PENDING = 1024  # bound memory under dry-run spam; oldest evicted first

    def __init__(
        self,
        *,
        ttl_seconds: float = 600.0,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ApprovalError(f"ttl_seconds must be finite and positive, got {ttl_seconds!r}")
        self.ttl_seconds = ttl_seconds
        self._clock = clock if clock is not None else time.monotonic
        self._pending: dict[str, _PendingApproval] = {}
        # Consumed tokens are kept until their original TTL passes, purely so a
        # replay gets the clearer "already used" message; after the TTL a replay
        # is refused as "not minted" anyway, so purging them bounds memory
        # without weakening single-use.
        self._consumed: dict[str, float] = {}  # token -> original expiry
        # Serialise mint/validate/consume so check-and-burn is atomic under a
        # multi-client (HTTP, BL-012) transport: without this, two concurrent
        # requests could both validate the same nonce before either burns it and
        # both execute (BL-104). The lock is per registry instance; the HTTP
        # transport gives each session its own registry, so this is one lock per
        # session: cross-session calls never contend, and a session's own nonces
        # are short-lived, so even same-session contention is negligible.
        self._lock = threading.Lock()

    def mint(
        self,
        *,
        action_id: str,
        target: str | None,
        tier: Tier,
        patterns_version: int,
    ) -> str:
        """Mint a fresh single-use nonce for one classified action."""
        with self._lock:
            now = self._clock()
            self._purge(now)
            token = secrets.token_urlsafe(16)
            self._pending[token] = _PendingApproval(
                action_id=action_id,
                target=target,
                tier=tier,
                patterns_version=patterns_version,
                expires_at=now + self.ttl_seconds,
            )
            return token

    @staticmethod
    def _eq(stored: str, presented: str) -> bool:
        """Constant-time token equality (BL-106). Compares on bytes so a hostile
        non-ASCII presented token cannot raise; a non-matching token never matches."""
        return secrets.compare_digest(
            stored.encode("ascii"), presented.encode("utf-8", "surrogatepass")
        )

    def _match_pending(self, token: str) -> str | None:
        """Return the matching pending token, compared in constant time. Scans every
        entry without breaking early so the timing does not reveal which (if any) matched."""
        match: str | None = None
        for stored in self._pending:
            if self._eq(stored, token):
                match = stored
        return match

    def _is_consumed(self, token: str) -> bool:
        found = False
        for stored in self._consumed:
            if self._eq(stored, token):
                found = True
        return found

    def _validate_locked(
        self,
        approval: Approval,
        *,
        action_id: str,
        target: str | None,
        tier: Tier,
        patterns_version: int,
    ) -> str:
        """Validate under the held lock; return the matched pending token, or raise."""
        if approval.action_id != action_id:
            raise ApprovalError("approval is not bound to this action")
        if self._is_consumed(approval.token):
            raise ApprovalError("approval already used; a retry requires a fresh approval")
        token = self._match_pending(approval.token)
        if token is None:
            raise ApprovalError(
                "approval token was not minted by this server for a pending action; "
                "run with dry_run=True to mint one"
            )
        pending = self._pending[token]
        if self._clock() > pending.expires_at:
            del self._pending[token]
            raise ApprovalError(
                "approval token has expired; re-run the dry run to mint a fresh one"
            )
        if pending.action_id != action_id:
            raise ApprovalError("approval token is bound to a different action")
        if pending.target != target:
            raise ApprovalError("approval token is bound to a different target")
        if pending.tier != tier:
            raise ApprovalError("approval token is bound to a different tier")
        if pending.patterns_version != patterns_version:
            raise ApprovalError(
                "classification patterns changed since this approval was minted; re-run the dry run"
            )
        return token

    def validate(
        self,
        approval: Approval,
        *,
        action_id: str,
        target: str | None,
        tier: Tier,
        patterns_version: int,
    ) -> None:
        """Check an approval without consuming it. Raises ``ApprovalError`` if invalid."""
        with self._lock:
            self._validate_locked(
                approval,
                action_id=action_id,
                target=target,
                tier=tier,
                patterns_version=patterns_version,
            )

    def consume(
        self,
        approval: Approval,
        *,
        action_id: str,
        target: str | None,
        tier: Tier,
        patterns_version: int,
    ) -> None:
        """Validate and burn the nonce atomically (BL-104): the check and the burn
        happen under one lock acquisition, so two concurrent requests presenting the
        same nonce cannot both pass validation before either burns it."""
        with self._lock:
            token = self._validate_locked(
                approval,
                action_id=action_id,
                target=target,
                tier=tier,
                patterns_version=patterns_version,
            )
            pending = self._pending.pop(token)
            self._consumed[token] = pending.expires_at

    def _purge(self, now: float) -> None:
        for tok in [t for t, pend in self._pending.items() if now > pend.expires_at]:
            del self._pending[tok]
        # Consumed entries past their original TTL can never be presented as
        # "already used" vs "not minted" differently: drop them (bounded memory).
        for tok in [t for t, expiry in self._consumed.items() if now > expiry]:
            del self._consumed[tok]
        while len(self._pending) >= self._MAX_PENDING:
            oldest = min(self._pending, key=lambda tok: self._pending[tok].expires_at)
            del self._pending[oldest]


@dataclass(frozen=True)
class RetryPolicy:
    """Bounded retry. ``max_retries`` defaults to one and must be a non-negative int."""

    max_retries: int = 1

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise BudgetError(f"max_retries must be non-negative, got {self.max_retries!r}")
