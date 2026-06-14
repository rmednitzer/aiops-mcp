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


def test_mode_ceiling_cannot_be_escalated_per_tool() -> None:
    """UCA-23 (SEC-3): the mode ceiling gates every tool uniformly; no per-call raise.

    There is no runtime ``set_mode`` tool. The mode is bound once at construction
    (``config.mode``) and ``Policy.check`` applies it to every tool, so a single call
    cannot lift its own ceiling by dressing up the tool name, the command, or a
    declared ``base_tier``. A mode refusal is a hard refusal (``denied`` False,
    ``requires_approval`` False), distinct from both the deny list and the approval
    gate, so no minted nonce can satisfy it.
    """
    guarded = Policy(Mode.GUARDED)
    # No combination smuggles a T3 past the guarded ceiling: a content cue, or a
    # declared base_tier=T3, still lands on the mode refusal, not an allow.
    for tool, command, base in (
        ("shell", "tofu destroy", Tier.T1),  # content -> T3
        ("act_talos", "talosctl reset", Tier.T1),  # content -> T3
        ("converge", None, Tier.T3),  # base floor -> T3
    ):
        decision = guarded.check(tool, command, base_tier=base)
        assert decision.tier == Tier.T3, (tool, command, base)
        assert decision.allowed is False
        assert decision.denied is False  # the mode gate, not the global deny list
        assert decision.requires_approval is False  # refused outright; no nonce lifts it
        assert decision.reason.startswith("mode=guarded")

    # Readonly caps at T0: every act tool is refused regardless of its declared base.
    readonly = Policy(Mode.READONLY)
    for tool, command, base in (
        ("act_shell", "systemctl restart nginx", Tier.T1),  # content -> T2
        ("act_runbook", "tofu apply", Tier.T1),  # content -> T2
        ("collector", None, Tier.T1),  # base floor -> T1
    ):
        decision = readonly.check(tool, command, base_tier=base)
        assert decision.allowed is False, (tool, command, base)
        assert decision.denied is False
        assert decision.requires_approval is False
        assert decision.reason.startswith("mode=readonly")

    # The ceiling is server-wide, not per tool: two different tools at the same tier
    # get the same refusal under one policy (no per-tool exemption or override).
    a = guarded.check("tool-a", "tofu destroy", base_tier=Tier.T1)
    b = guarded.check("tool-b", "tofu destroy", base_tier=Tier.T1)
    assert a.allowed is False and b.allowed is False
