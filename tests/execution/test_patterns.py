"""SEC-3: classification is conservative (rounds up; sudo/doas/pkexec floor at T2)."""

from __future__ import annotations

from praxis.execution.patterns import PATTERNS_VERSION, Tier, command_tier, deny_match
from praxis.execution.policy import classify


def test_priv_escalation_is_at_least_t2() -> None:
    for cmd in ("sudo ls", "doas whoami", "pkexec id", "sudo apt update", "su - root"):
        assert command_tier(cmd) >= Tier.T2, cmd


def test_classify_rounds_up() -> None:
    # The base tier is a floor; a benign command never lowers it.
    assert classify("act", "echo hi", base_tier=Tier.T1) == Tier.T1
    # A read collector stays T0 for a read command.
    assert classify("collector", "cat /etc/os-release", base_tier=Tier.T0) == Tier.T0
    # Command content rounds the tier up above the base.
    assert classify("shell", "tofu apply", base_tier=Tier.T1) == Tier.T2
    assert classify("shell", "rm -rf /var/tmp/x", base_tier=Tier.T1) == Tier.T3
    # Ambiguity (matches T2 escalation and a T3 verb) rounds to the maximum.
    assert classify("shell", "sudo tofu destroy", base_tier=Tier.T0) == Tier.T3


def test_deny_catches_root_wipe_and_forkbomb() -> None:
    assert deny_match("rm -rf /") is not None
    assert deny_match("rm -rf / ") is not None
    assert deny_match(":(){ :|:& };:") is not None
    assert deny_match("mkfs.ext4 /dev/sda1") is not None
    assert deny_match("dd if=/dev/zero of=/dev/nvme0n1") is not None
    # A benign read is not denied.
    assert deny_match("ls -la /var/log") is None
    assert deny_match("rm -rf /var/tmp/build") is None


def test_patterns_version_is_tracked() -> None:
    assert isinstance(PATTERNS_VERSION, int)
    assert PATTERNS_VERSION >= 1
