"""Skill manifests and a minimal SKILL.md frontmatter parser (ADR-0010).

A skill is a bundle: ``SKILL.md`` with simple YAML-style frontmatter (name,
description, kind, optional inputs/outputs) plus optional ``references/``. To stay
self-contained, the frontmatter parser handles the flat ``key: value`` subset this
project uses; no YAML dependency is taken. Untrusted bundles are loaded with
``allow_contract=False``: this loader never imports or executes bundle code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

HOST_KNOWLEDGE = "host-knowledge"
TOOL = "tool"
KINDS = frozenset({HOST_KNOWLEDGE, TOOL})


@dataclass(frozen=True)
class SkillManifest:
    name: str
    description: str
    kind: str
    path: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split ``---`` frontmatter from the body. Returns ({}, text) if absent."""
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end: int | None = None
    for index in range(1, len(lines)):
        if lines[index].strip() == "---":
            end = index
            break
    if end is None:
        return {}, text
    meta: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta, "\n".join(lines[end + 1 :])


def _csv(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def load_skill(skill_md: Path, *, allow_contract: bool = False) -> SkillManifest | None:
    """Load one bundle's manifest. ``allow_contract`` is accepted for API parity but
    is never honoured here: this loader does not execute bundle code."""
    if allow_contract:
        # Defense-in-depth: even if asked, this loader never runs bundle code.
        allow_contract = False
    try:
        text = skill_md.read_text(encoding="utf-8")
    except OSError:
        return None
    meta, _ = parse_frontmatter(text)
    name = meta.get("name", "").strip()
    description = meta.get("description", "").strip()
    kind = meta.get("kind", "").strip()
    if not name or not description or kind not in KINDS:
        return None
    return SkillManifest(
        name=name,
        description=description,
        kind=kind,
        path=str(skill_md.parent),
        inputs=_csv(meta.get("inputs", "")),
        outputs=_csv(meta.get("outputs", "")),
    )
