#!/usr/bin/env python3
"""Validate the compliance catalog against code, STPA, and the prose map (BL-031, ADR-0021).

Exits non-zero with one line per violation when the catalog has drifted from the
codebase (a missing or stale module path, a control that does not back-cite its SEC
constraint, an uncovered framework, a missing proving test); exits 0 when every
bidirectional cross-reference rule holds. Wired into ``make validate-compliance`` and
the ``ci-success`` aggregate gate, and re-run inside the test suite.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.governance.validate import run  # noqa: E402

CATALOG = ROOT / "docs" / "governance" / "compliance-controls.json"


def main() -> int:
    errors = run(ROOT, CATALOG)
    if errors:
        print(f"compliance catalog: {len(errors)} violation(s) (run `make validate-compliance`):")
        for err in errors:
            print(f"  - {err}")
        return 1
    print("compliance catalog: consistent with code, STPA constraints, and the compliance map")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
