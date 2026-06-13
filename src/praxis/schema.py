"""Generated JSON Schemas and a drift guard (ADR-0010; the schema-drift guard).

``build_schemas`` is the single source of truth for the committed schema documents
under ``docs/schema/``. ``make schema`` writes them; the test suite calls
``check_schemas`` so a change to the skill-manifest shape or the registered tool
set that is not regenerated fails the build.
"""

from __future__ import annotations

import json
from pathlib import Path

from praxis.governance.catalog import ComplianceCatalog
from praxis.skills.manifest import SkillFrontmatter


def _skill_manifest_schema() -> dict[str, object]:
    # Generated from the pydantic frontmatter model (one source of truth, ADR-0014).
    return dict(SkillFrontmatter.model_json_schema())


def _compliance_catalog_schema() -> dict[str, object]:
    # The compliance catalog model is the source of truth for its schema too (BL-031).
    return dict(ComplianceCatalog.model_json_schema())


def _tools_manifest() -> dict[str, object]:
    # Imported lazily to avoid a server import at module load.
    from praxis.server import build_registry

    return {
        "title": "RegisteredTools",
        "tools": [spec.to_mcp() for spec in build_registry().specs()],
    }


def build_schemas() -> dict[str, dict[str, object]]:
    return {
        "skill-manifest.schema.json": _skill_manifest_schema(),
        "tools.schema.json": _tools_manifest(),
        "compliance-controls.schema.json": _compliance_catalog_schema(),
    }


def _render(schema: dict[str, object]) -> str:
    return json.dumps(schema, indent=2, sort_keys=True) + "\n"


def write_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, schema in build_schemas().items():
        path = out_dir / name
        path.write_text(_render(schema), encoding="utf-8")
        written.append(path)
    return written


def check_schemas(out_dir: Path) -> list[str]:
    """Return the names of schema files that are missing or drifted."""
    drift: list[str] = []
    for name, schema in build_schemas().items():
        path = out_dir / name
        if not path.exists():
            drift.append(name)
            continue
        if json.loads(path.read_text(encoding="utf-8")) != schema:
            drift.append(name)
    return drift
