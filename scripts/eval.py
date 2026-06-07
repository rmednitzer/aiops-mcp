#!/usr/bin/env python3
"""Dispatch eval gate (ADR-0010). Exits non-zero if P@1 or MRR fall below threshold."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.skills.eval import run_eval  # noqa: E402

P_AT_1_MIN = 0.80
MRR_MIN = 0.85


def main() -> int:
    result = run_eval(ROOT / "skills", ROOT / "evaluation" / "skills_golden.json")
    print(f"dispatch eval: P@1={result.p_at_1:.3f} MRR={result.mrr:.3f} (n={result.n})")
    for query, expected, got in result.failures:
        print(f"  MISS: {query!r} expected {expected} got {got or '<none>'}")
    if result.p_at_1 < P_AT_1_MIN or result.mrr < MRR_MIN:
        print(f"FAIL: thresholds P@1>={P_AT_1_MIN} MRR>={MRR_MIN}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
