"""SEC-1: the deny list is global, unconditional, and evaluated first."""

from __future__ import annotations

from praxis.execution.patterns import Tier
from praxis.execution.policy import Mode, Policy


def test_deny_is_global_and_first() -> None:
    # The deny list applies in every mode, including the most permissive (open),
    # and returns a denied decision regardless of tier or approval.
    for mode in (Mode.OPEN, Mode.GUARDED, Mode.READONLY):
        decision = Policy(mode).check("shell", "rm -rf /")
        assert decision.allowed is False, mode
        assert decision.denied is True, mode


def test_readonly_refuses_above_t0() -> None:
    policy = Policy(Mode.READONLY)
    assert policy.check("collector", "ls", base_tier=Tier.T0).allowed is True
    assert policy.check("shell", "systemctl restart nginx").allowed is False


def test_guarded_refuses_t3_allows_t2() -> None:
    policy = Policy(Mode.GUARDED)
    assert policy.check("shell", "tofu apply", base_tier=Tier.T1).allowed is True
    decision = policy.check("shell", "tofu destroy", base_tier=Tier.T1)
    assert decision.allowed is False
    assert decision.tier == Tier.T3


def test_t2_and_above_require_approval() -> None:
    policy = Policy(Mode.OPEN)
    t2 = policy.check("shell", "systemctl restart nginx")
    assert t2.tier == Tier.T2
    assert t2.requires_approval is True
    t3 = policy.check("shell", "tofu destroy", base_tier=Tier.T1)
    assert t3.allowed is True
    assert t3.tier == Tier.T3
    assert t3.requires_approval is True


def test_t0_needs_no_approval() -> None:
    decision = Policy(Mode.OPEN).check("collector", "cat /etc/hostname", base_tier=Tier.T0)
    assert decision.requires_approval is False
