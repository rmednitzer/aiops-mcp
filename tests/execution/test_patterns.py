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
    # F-004: root-equivalent spellings are denied too, not merely T3-gated.
    assert deny_match("rm -rf //") is not None
    assert deny_match("rm -rf /*") is not None
    assert deny_match("rm -rf /.") is not None
    assert deny_match("rm -r //") is not None
    assert deny_match(":(){ :|:& };:") is not None
    assert deny_match("mkfs.ext4 /dev/sda1") is not None
    assert deny_match("dd if=/dev/zero of=/dev/nvme0n1") is not None
    # A benign read is not denied, and a real subpath of / is not over-matched.
    assert deny_match("ls -la /var/log") is None
    assert deny_match("rm -rf /var/tmp/build") is None
    assert deny_match("rm -rf /etc") is None


def test_deny_catches_recursive_perms_on_root() -> None:
    # A recursive chmod/chown of / is unrecoverable; it is a global deny (BL-040).
    assert deny_match("chmod -R 777 /") is not None
    assert deny_match("chmod 777 -R /") is not None
    assert deny_match("chown -R root:root /") is not None
    # A scoped recursive chmod is not the root deny.
    assert deny_match("chmod -R 755 /var/www") is None


def test_etc_writes_are_at_least_t2() -> None:
    # A write under /etc reconfigures the host; it must not classify as a T0 read
    # (the reproduced bug: a space before /etc/ slipped past the old word boundary)
    # (BL-040).
    for cmd in (
        "chmod 777 /etc/shadow",
        "cp evil /etc/passwd",
        "tee /etc/hosts",
        "echo x > /etc/hosts",
    ):
        assert command_tier(cmd) >= Tier.T2, cmd
    # A read of a path under /etc stays T0.
    assert command_tier("cat /etc/os-release") == Tier.T0


def test_patterns_version_is_tracked() -> None:
    assert isinstance(PATTERNS_VERSION, int)
    assert PATTERNS_VERSION >= 1
