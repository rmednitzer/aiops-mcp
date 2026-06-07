#!/usr/bin/env python3
"""Verify the audit hash chain and Merkle checkpoints (ADR-0008). Fail-closed."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.audit import verify_evidence  # noqa: E402


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("usage: verify_audit.py <audit.jsonl> [evidence.jsonl]")
        return 2
    audit = Path(args[0])
    evidence = Path(args[1]) if len(args) > 1 else audit.with_suffix(".evidence.jsonl")
    result = verify_evidence(audit, evidence)
    print(
        f"audit verify: ok={result.ok} checkpoints={result.checkpoints} "
        f"reason={result.reason or 'none'}"
    )
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
