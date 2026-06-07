#!/usr/bin/env python3
"""Generate (or --check) the committed JSON Schemas under docs/schema/ (ADR-0010)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from praxis.schema import check_schemas, write_schemas  # noqa: E402

SCHEMA_DIR = ROOT / "docs" / "schema"


def main() -> int:
    if "--check" in sys.argv[1:]:
        drift = check_schemas(SCHEMA_DIR)
        if drift:
            print(f"schema drift detected: {', '.join(drift)} (run `make schema`)")
            return 1
        print("schema up to date")
        return 0
    written = write_schemas(SCHEMA_DIR)
    print(f"wrote {', '.join(p.name for p in written)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
