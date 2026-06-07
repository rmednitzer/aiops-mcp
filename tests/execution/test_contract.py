"""Contracts: predicates (HARD/SOFT), budgets (non-finite rejection), single-use approvals."""

from __future__ import annotations

import math

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


def test_approval_is_single_use() -> None:
    registry = ApprovalRegistry()
    approval = Approval(action_id="a1", token="tok")
    registry.consume(approval, expected_action_id="a1", expected_token="tok")
    with pytest.raises(ApprovalError):
        registry.consume(approval, expected_action_id="a1", expected_token="tok")


def test_approval_binding_enforced() -> None:
    registry = ApprovalRegistry()
    approval = Approval(action_id="a1", token="tok")
    with pytest.raises(ApprovalError):
        registry.consume(approval, expected_action_id="other", expected_token="tok")
    with pytest.raises(ApprovalError):
        registry.consume(approval, expected_action_id="a1", expected_token="wrong")


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
