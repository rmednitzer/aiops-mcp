"""The schema-drift guard, run as part of the suite (ADR-0010).

If the skill-manifest shape or the registered tool set changes without
regenerating docs/schema/ (`make schema`), this fails.
"""

from __future__ import annotations

from pathlib import Path

from praxis.schema import check_schemas

_ROOT = Path(__file__).resolve().parents[1]


def test_no_schema_drift() -> None:
    drift = check_schemas(_ROOT / "docs" / "schema")
    assert drift == [], f"regenerate with `make schema`: {drift}"
