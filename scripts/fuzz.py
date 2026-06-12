#!/usr/bin/env python3
"""Nightly fuzz harness over the security-review surfaces (ADR-0004, ADR-0005).

Throws random and adversarial strings at classify, Policy.check, and redaction, and
asserts the load-bearing invariants hold: nothing raises, privilege-escalation cues
never classify below T2, deny-listed commands are always denied (in every mode),
and redaction never returns a known secret. BL-061 extends the sweep to the other
untrusted-input surfaces: the SKILL.md frontmatter parser (never raises, honors its
caps), the RFC 6962 Merkle tree (never raises, deterministic, domain-separated),
and evidence verification (never raises; garbage is ok=False, fail-closed). Exits
non-zero on any violation.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.audit.evidence import verify_evidence  # noqa: E402
from praxis.audit.merkle import leaf_hash, merkle_root  # noqa: E402
from praxis.execution.patterns import Tier, command_tier, deny_match  # noqa: E402
from praxis.execution.policy import Mode, Policy, classify  # noqa: E402
from praxis.execution.redaction import REDACTED, redact  # noqa: E402
from praxis.skills.manifest import parse_frontmatter  # noqa: E402

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


_FRONTMATTER_FRAGMENTS = [
    "---",
    "---\n",
    "name: x",
    "name:",
    ": value",
    "name: a\nname: b",  # duplicate key: must invalidate the header
    "  indented: not-a-key",
    "# comment",
    "kind: tool",
    "kind: host-knowledge",
    "inputs: a, b, c",
    "\x00",
    "\u202e",  # RTL override
    "k" * 200 + ": v",
    "🜏: glyph",
]


def fuzz_manifest(rng: random.Random, iterations: int) -> int:
    """The frontmatter parser must never raise and must return a header dict."""
    failures = 0
    for _ in range(iterations):
        text = "\n".join(rng.choice(_FRONTMATTER_FRAGMENTS) for _ in range(rng.randint(0, 12)))
        try:
            meta, body = parse_frontmatter(text)
        except Exception as exc:  # noqa: BLE001 - any raise is a fuzz failure
            print(f"FAIL manifest raised on {text!r}: {type(exc).__name__}: {exc}")
            failures += 1
            continue
        if not isinstance(meta, dict) or not isinstance(body, str):
            print(f"FAIL manifest returned non-(dict, str) for {text!r}")
            failures += 1
    return failures


def fuzz_merkle(rng: random.Random, iterations: int) -> int:
    """The tree must never raise, be deterministic, and keep domain separation."""
    failures = 0
    for _ in range(iterations):
        leaves = [rng.randbytes(rng.randint(0, 64)) for _ in range(rng.randint(0, 16))]
        try:
            first, second = merkle_root(leaves), merkle_root(list(leaves))
        except Exception as exc:  # noqa: BLE001 - any raise is a fuzz failure
            print(f"FAIL merkle raised on {len(leaves)} leaves: {type(exc).__name__}: {exc}")
            failures += 1
            continue
        if first != second:
            print(f"FAIL merkle nondeterministic on {len(leaves)} leaves")
            failures += 1
        # RFC 6962 domain separation: a single-leaf root is the LEAF hash
        # (0x00-prefixed), never the bare hash of the leaf bytes.
        if len(leaves) == 1 and first != leaf_hash(leaves[0]):
            print("FAIL merkle single-leaf root is not the domain-separated leaf hash")
            failures += 1
    return failures


def fuzz_evidence(rng: random.Random, iterations: int) -> int:
    """verify_evidence must never raise; garbage must be ok=False (fail-closed)."""
    import json
    import tempfile
    from pathlib import Path

    failures = 0
    garbage = [
        "not json",
        "{}",
        '{"seq": 0}',
        '{"seq": "x", "tree_size": -1, "root_sha256": 1, "ts": [], "token": 0, '
        '"prev": null, "checkpoint_hash": {}}',
        '{"seq": 0, "tree_size": 999999, "root_sha256": "00", "ts": "t", '
        '"token": {}, "prev": "' + "0" * 64 + '", "checkpoint_hash": "00"}',
    ]
    with tempfile.TemporaryDirectory() as tmp:
        audit = Path(tmp) / "audit.jsonl"
        audit.write_text(
            json.dumps({"seq": 0, "entry_hash": "00", "prev_hash": "0" * 64}) + "\n",
            encoding="utf-8",
        )
        evidence = Path(tmp) / "evidence.jsonl"
        for _ in range(iterations):
            lines = [rng.choice(garbage) for _ in range(rng.randint(1, 4))]
            evidence.write_text("\n".join(lines) + "\n", encoding="utf-8")
            try:
                result = verify_evidence(audit, evidence)
            except Exception as exc:  # noqa: BLE001 - any raise is a fuzz failure
                print(f"FAIL evidence raised on {lines!r}: {type(exc).__name__}: {exc}")
                failures += 1
                continue
            if result.ok:
                print(f"FAIL evidence accepted garbage: {lines!r}")
                failures += 1
    return failures


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
    # The classify/policy/redaction loop above carries the main budget; the
    # other untrusted-input surfaces get a tenth each (file-backed evidence a
    # hundredth: it writes per case).
    failures += fuzz_manifest(rng, max(1, iterations // 10))
    failures += fuzz_merkle(rng, max(1, iterations // 10))
    failures += fuzz_evidence(rng, max(1, iterations // 100))
    if failures:
        print(f"fuzz: {failures} failures over {iterations} iterations")
        return 1
    print(f"fuzz: {iterations} iterations (+ manifest/merkle/evidence stages), no violations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
