"""BL-019: the classification probe includes the tool name, not the command alone."""

from __future__ import annotations

from praxis.execution import Mode, Policy, Tier, classify


def test_deny_probe_spans_tool_and_command() -> None:
    # The deny pattern for a force-push to trunk needs the "git" cue; with the
    # tool name in the probe, the cue cannot be split across tool and command.
    policy = Policy(Mode.OPEN)
    decision = policy.check("git", "push --force origin main", base_tier=Tier.T1)
    assert decision.allowed is False
    assert decision.denied is True


def test_classify_probe_includes_tool_name() -> None:
    # Command alone carries no tier cue; the tool name supplies it.
    assert classify("ssh", "echo hi > /tmp/x", base_tier=Tier.T0) >= Tier.T1
    assert classify("systemctl", "restart nginx", base_tier=Tier.T0) == Tier.T2


def test_benign_tool_names_do_not_misclassify() -> None:
    # Registered tool names must not collide with the patterns (the emergency
    # stop and the read tools stay T0).
    for tool in (
        "emergency_stop",
        "query_facts",
        "fact_history",
        "ingest_observation",
        "drift_scan",
    ):
        assert classify(tool, None, base_tier=Tier.T0) == Tier.T0
