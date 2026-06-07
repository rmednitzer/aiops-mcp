"""Classification patterns: the sole security-review surface of the executor.

This module is the one place where the meaning of a command (its blast radius) is
encoded. Every change here is a security review and MUST bump ``PATTERNS_VERSION``
so the change is visible in the audit trail (ADR-0004, ADR-0005; SEC-3).

The tiers (ADR-0004):

- T0 observe: read-only.
- T1 reversible: act, log, notify.
- T2 stateful: human confirm with a rollback plan.
- T3 irreversible: typed token plus before/after evidence; one target at a time.

Classification is conservative and rounds up (`execution.policy.classify`). The
deny set is global and unconditional, evaluated before any tier gate
(`execution.policy.Policy.check`).
"""

from __future__ import annotations

import re
from enum import IntEnum

# Bump on EVERY change to the pattern sets below. The audit record stamps this
# value so a reviewer can tie a classification to the exact ruleset that produced
# it (SEC-3).
PATTERNS_VERSION = 1


class Tier(IntEnum):
    """Authority tiers, ordered so that ``max`` implements the round-up rule."""

    T0 = 0
    T1 = 1
    T2 = 2
    T3 = 3

    @property
    def label(self) -> str:
        return self.name


def _compile(patterns: list[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


# Global deny list. These never run, in any mode, regardless of approval. Keep it
# small and unambiguous: it is the unconditional floor beneath every gate (SEC-1).
DENY: tuple[re.Pattern[str], ...] = _compile(
    [
        r"\brm\s+(-[a-z]*r[a-z]*\s+)?(-[a-z]*f[a-z]*\s+)?/\s*($|\s)",  # rm -rf /
        r"\brm\s+-[a-z]*\s+/\s*($|\s)",
        r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # classic fork bomb
        r"\bmkfs(\.\w+)?\b.*/dev/(sd|nvme|vd|hd)",  # format a real disk
        r"\bdd\b[^\n]*\bof=/dev/(sd|nvme|vd|hd)",  # dd onto a raw disk
        r"\bwipefs\b.*/dev/",
        r">\s*/dev/(sd|nvme|vd|hd)\w*",  # redirect onto a raw disk
        r"\b(chmod|chown)\s+-[a-z]*R[a-z]*\s+/\s*($|\s)",  # recursive perms on /
        r"\bgit\b.*\bpush\b.*--force.*\b(main|master)\b",  # force-push to trunk
    ]
)

# Privilege-escalation cues. Their presence floors the tier at T2 (SEC-3, ADR-0004
# invariant 2). They do not by themselves deny.
PRIV_ESCALATION: tuple[re.Pattern[str], ...] = _compile(
    [
        r"\bsudo\b",
        r"\bdoas\b",
        r"\bpkexec\b",
        r"\bsu\s+-",
        r"\brunas\b",  # windows
    ]
)

# T3 irreversible. Destructive, not cleanly reversible without restore.
TIER3: tuple[re.Pattern[str], ...] = _compile(
    [
        r"\brm\s+-[a-z]*r",  # recursive delete (non-root; root is DENY)
        r"\bmkfs(\.\w+)?\b",
        r"\bdd\b[^\n]*\bof=",
        r"\b(shutdown|poweroff|halt|reboot)\b",
        r"\btalosctl\b[^\n]*\b(reset|upgrade|bootstrap|wipe)\b",
        r"\b(tofu|terraform)\b[^\n]*\bdestroy\b",
        r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\b(userdel|groupdel)\b",
        r"\b(lvremove|vgremove|pvremove)\b",
        r"\bredfish\b[^\n]*\b(reset|poweroff|forceoff)\b",
        r"\bipmitool\b[^\n]*\bchassis\s+power\s+(off|cycle|reset)\b",
    ]
)

# T2 stateful. Changes state but with a reasonable rollback path.
TIER2: tuple[re.Pattern[str], ...] = _compile(
    [
        r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask)\b",
        r"\b(apt|apt-get|dnf|yum|zypper|pacman)\s+(install|remove|purge|upgrade)\b",
        r"\bpip\s+(install|uninstall)\b",
        r"\b(tofu|terraform)\b[^\n]*\bapply\b",
        r"\bansible-playbook\b(?![^\n]*--check)",  # apply (a --check run is T0)
        r"\b(docker|podman)\s+(run|rm|stop|kill|restart)\b",
        r"\bkubectl\s+(apply|delete|scale|rollout|patch|edit)\b",
        r"\btalosctl\b[^\n]*\bapply-config\b",
        r"\b(kill|pkill|killall)\b",
        r"\b(mount|umount)\b",
        r"\b(iptables|nft|ufw|firewall-cmd)\b[^\n]*\b(add|insert|delete|deny|allow|drop|reject)\b",
        r"\b(useradd|usermod|groupadd|passwd)\b",
        r"\bgit\b[^\n]*\bpush\b",
        r"\b(cp|mv|tee|truncate|chmod|chown|ln)\b[^\n]*\b/etc/\b",  # write under /etc
        r">\s*/etc/\b",
    ]
)

# T1 reversible. Acts but is trivially undone or has no lasting state.
TIER1: tuple[re.Pattern[str], ...] = _compile(
    [
        r"\b(touch|mkdir)\b",
        r"\becho\b[^\n]*>",  # write to a file via redirect
        r"\bgit\b[^\n]*\b(add|commit|checkout|switch|stash)\b",
        r"\b(docker|podman)\s+(pull|build|tag)\b",
    ]
)


def deny_match(command: str) -> re.Pattern[str] | None:
    """Return the first deny pattern that matches, or None."""
    for pat in DENY:
        if pat.search(command):
            return pat
    return None


def _any(patterns: tuple[re.Pattern[str], ...], command: str) -> bool:
    return any(p.search(command) for p in patterns)


def command_tier(command: str) -> Tier:
    """The tier implied by a command's content, before applying a base floor.

    Checks highest-severity first and floors privilege escalation at T2, so the
    result is the maximum applicable tier (the round-up rule, SEC-3).
    """
    tier = Tier.T0
    if _any(TIER3, command):
        tier = Tier.T3
    elif _any(TIER2, command):
        tier = Tier.T2
    elif _any(TIER1, command):
        tier = Tier.T1
    if _any(PRIV_ESCALATION, command):
        tier = max(tier, Tier.T2)
    return tier
