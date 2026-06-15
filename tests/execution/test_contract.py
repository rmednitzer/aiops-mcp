"""Contracts: predicates (HARD/SOFT), budgets (non-finite rejection), single-use approvals."""

from __future__ import annotations

import math
import threading

import pytest

from praxis.execution.contract import (
    Approval,
    ApprovalError,
    ApprovalRegistry,
    BudgetError,
    BudgetTracker,
    Contract,
    Predicate,
    RetryPolicy,
    Severity,
)
from praxis.execution.patterns import Tier


def test_budget_rejects_non_finite_limits() -> None:
    for bad in (math.nan, math.inf, -math.inf):
        with pytest.raises(BudgetError):
            BudgetTracker(max_usd=bad)
    with pytest.raises(BudgetError):
        BudgetTracker(max_actions=-1)


def test_budget_charge_validates_and_enforces() -> None:
    budget = BudgetTracker(max_actions=2)
    budget.charge()
    budget.charge()
    with pytest.raises(BudgetError):
        budget.charge()
    with pytest.raises(BudgetError):
        BudgetTracker(max_usd=1.0).charge(usd=math.nan)


def test_retry_policy_validates() -> None:
    assert RetryPolicy().max_retries == 1
    with pytest.raises(BudgetError):
        RetryPolicy(max_retries=-1)


def test_approval_is_minted_and_single_use() -> None:
    registry = ApprovalRegistry()
    token = registry.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    approval = Approval(action_id="a1", token=token)
    # validate is non-consuming; consume burns the nonce.
    registry.validate(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    with pytest.raises(ApprovalError, match="already used"):
        registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)


def test_unminted_token_is_refused() -> None:
    # The caller cannot conjure a valid token: only the server mints (BL-072).
    registry = ApprovalRegistry()
    approval = Approval(action_id="a1", token="APPROVE-a1")
    with pytest.raises(ApprovalError, match="not minted"):
        registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)


def test_approval_binding_enforced() -> None:
    registry = ApprovalRegistry()
    token = registry.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    with pytest.raises(ApprovalError, match="different action"):
        registry.consume(
            Approval(action_id="other", token=token),
            action_id="other",
            target="axiom",
            tier=Tier.T2,
            patterns_version=3,
        )
    approval = Approval(action_id="a1", token=token)
    with pytest.raises(ApprovalError, match="different target"):
        registry.consume(approval, action_id="a1", target="atlas", tier=Tier.T2, patterns_version=3)
    with pytest.raises(ApprovalError, match="different tier"):
        registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T3, patterns_version=3)
    with pytest.raises(ApprovalError, match="patterns changed"):
        registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=4)
    # The binding failures above did not consume the nonce: the correct binding works.
    registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)


def test_approval_ttl_expires() -> None:
    now = {"t": 0.0}
    registry = ApprovalRegistry(ttl_seconds=600.0, clock=lambda: now["t"])
    token = registry.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    approval = Approval(action_id="a1", token=token)
    now["t"] = 601.0
    with pytest.raises(ApprovalError, match="expired"):
        registry.validate(
            approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3
        )


def test_pending_approvals_are_bounded() -> None:
    # Dry-run spam cannot grow the pending set without bound; the oldest mints
    # are evicted first (fail closed: an evicted nonce simply cannot approve).
    registry = ApprovalRegistry()
    first = registry.mint(action_id="a0", target="h", tier=Tier.T2, patterns_version=3)
    for i in range(1, ApprovalRegistry._MAX_PENDING + 1):
        registry.mint(action_id=f"a{i}", target="h", tier=Tier.T2, patterns_version=3)
    with pytest.raises(ApprovalError, match="not minted"):
        registry.validate(
            Approval(action_id="a0", token=first),
            action_id="a0",
            target="h",
            tier=Tier.T2,
            patterns_version=3,
        )


def test_approval_consume_is_atomic_under_concurrency() -> None:
    # BL-104: two concurrent requests presenting the same nonce must not both succeed.
    # The check-and-burn is atomic (one lock), so exactly one consumes; the other is
    # refused. Without the lock the validate-then-pop would let both pass validation.
    registry = ApprovalRegistry()
    token = registry.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    approval = Approval(action_id="a1", token=token)
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    record_lock = threading.Lock()

    def attempt() -> None:
        barrier.wait(timeout=5)
        try:
            registry.consume(
                approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3
            )
            result = "ok"
        except ApprovalError:
            result = "refused"
        with record_lock:
            outcomes.append(result)

    threads = [threading.Thread(target=attempt, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive(), "a consume thread hung"
    assert sorted(outcomes) == ["ok", "refused"], outcomes


def test_nonce_is_isolated_to_its_registry() -> None:
    # Per-session isolation (BL-104): each HTTP session has its own registry, so a nonce
    # minted in one session cannot be consumed by another.
    owner = ApprovalRegistry()
    other = ApprovalRegistry()
    token = owner.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    approval = Approval(action_id="a1", token=token)
    with pytest.raises(ApprovalError, match="not minted"):
        other.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    # The cross-registry attempt did not burn it: the owning registry still consumes it.
    owner.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)


def test_non_ascii_token_is_refused_not_raised() -> None:
    # The constant-time comparison (BL-106) runs on bytes, so a hostile non-ASCII token
    # is cleanly refused rather than raising a TypeError out of the audited path.
    registry = ApprovalRegistry()
    registry.mint(action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)
    approval = Approval(action_id="a1", token="tøken-ünicode")
    with pytest.raises(ApprovalError, match="not minted"):
        registry.consume(approval, action_id="a1", target="axiom", tier=Tier.T2, patterns_version=3)


def test_budget_record_spend_never_raises_on_ceiling() -> None:
    # Post-execute accounting records the overspend; the NEXT charge fails (BL-074).
    budget = BudgetTracker(max_wall_seconds=10.0)
    budget.record_spend(wall_seconds=60.0)
    assert budget.wall_seconds == 60.0
    with pytest.raises(BudgetError, match="wall budget exceeded"):
        budget.charge(actions=1)


def test_predicate_hard_and_soft() -> None:
    contract = Contract[int](
        preconditions=[
            Predicate[int]("positive", lambda x: x > 0, Severity.HARD, "must be positive"),
            Predicate[int]("even", lambda x: x % 2 == 0, Severity.SOFT, "prefer even"),
        ]
    )
    soft_only = contract.check_pre(3)  # positive ok, even fails (soft)
    assert Contract.hard_failures(soft_only) == []
    with_hard = contract.check_pre(-1)  # positive fails (hard)
    assert len(Contract.hard_failures(with_hard)) == 1


def test_throwing_predicate_is_hard() -> None:
    def boom(_: int) -> bool:
        raise ValueError("predicate blew up")

    contract = Contract[int](preconditions=[Predicate[int]("boom", boom, Severity.SOFT, "x")])
    violations = contract.check_pre(1)
    assert len(Contract.hard_failures(violations)) == 1
