#!/usr/bin/env python3
"""Nightly fuzz harness over the security-review surfaces (ADR-0004, ADR-0005).

Throws random and adversarial strings at classify, Policy.check, and redaction, and
asserts the load-bearing invariants hold: nothing raises, privilege-escalation cues
never classify below T2, deny-listed commands are always denied (in every mode),
and redaction never returns a known secret. Exits non-zero on any violation.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.execution.patterns import Tier, command_tier, deny_match  # noqa: E402
from praxis.execution.policy import Mode, Policy, classify  # noqa: E402
from praxis.execution.redaction import REDACTED, redact  # noqa: E402

_FRAGMENTS = [
    "ls",
    "cat",
    "sudo",
    "doas",
    "pkexec",
    "rm -rf /",
    "rm -rf /var/tmp/x",
    "tofu apply",
    "tofu destroy",
    "systemctl restart nginx",
    "talosctl reset",
    "ansible-playbook site.yml",
    "ansible-playbook site.yml --check",
    ";",
    "&&",
    "| sh",
    "$(",
    "`",
    "../",
    "\n",
    "password=hunter2",
    "AKIAIOSFODNN7EXAMPLE",
    "\x00",
    "ghp_0123456789abcdefghijABCDEFG",
    "echo hi > /etc/passwd",
]


def _random_command(rng: random.Random) -> str:
    return " ".join(rng.choice(_FRAGMENTS) for _ in range(rng.randint(1, 6)))


def main() -> int:
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
    rng = random.Random(1337)  # noqa: S311 - fuzzing inputs, not cryptographic use
    failures = 0
    for _ in range(iterations):
        command = _random_command(rng)
        try:
            tier = classify("fuzz", command, base_tier=Tier.T0)
            for mode in (Mode.OPEN, Mode.GUARDED, Mode.READONLY):
                Policy(mode).check("fuzz", command, base_tier=Tier.T0)
            redacted = redact(command)
        except Exception as exc:  # noqa: BLE001 - any raise is a fuzz failure
            print(f"FAIL raised on {command!r}: {type(exc).__name__}: {exc}")
            failures += 1
            continue
        if any(cue in command for cue in ("sudo", "doas", "pkexec")) and tier < Tier.T2:
            print(f"FAIL priv-escalation under-rated: {command!r} -> {tier.label}")
            failures += 1
        # A deny-listed command must be denied in every mode, including the most
        # permissive (the real invariant; substring checks are not the deny list).
        if deny_match(command) is not None and Policy(Mode.OPEN).check("fuzz", command).allowed:
            print(f"FAIL deny bypass in open mode: {command!r}")
            failures += 1
        if "password=hunter2" in command and "hunter2" in redacted:
            print(f"FAIL secret leaked through redaction: {command!r}")
            failures += 1
        _ = command_tier(command)
        _ = REDACTED
    if failures:
        print(f"fuzz: {failures} failures over {iterations} iterations")
        return 1
    print(f"fuzz: {iterations} iterations, no violations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
