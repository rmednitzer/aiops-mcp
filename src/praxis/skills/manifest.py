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

# A SKILL.md is a small header plus prose. These caps defend the parser against a
# crafted or runaway bundle without affecting any legitimate skill (BL-057).
_MAX_SKILL_BYTES = 1 * 1024 * 1024
_MAX_FRONTMATTER_BYTES = 64 * 1024


@dataclass(frozen=True)
class SkillManifest:
    name: str
    description: str
    kind: str
    path: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split ``---`` frontmatter from the body. Returns ({}, text) if absent/malformed.

    Hardened against crafted bundles (BL-057): the opening and closing fences must be
    exactly ``---`` (after trailing-whitespace strip, so an indented ``---`` is not a
    fence), the header is size-capped, an indented line is not treated as a flat
    top-level key (this minimal parser does not nest), and a duplicate key invalidates
    the whole header rather than silently last-wins, so a manifest cannot show one
    value to a human reader and route under another.
    """
    lines = text.splitlines()
    if not lines or lines[0].rstrip() != "---":
        return {}, text
    end: int | None = None
    for index in range(1, len(lines)):
        if lines[index].rstrip() == "---":
            end = index
            break
    if end is None:
        return {}, text
    header_lines = lines[1:end]
    header = "\n".join(header_lines)
    if len(header.encode("utf-8", errors="surrogatepass")) > _MAX_FRONTMATTER_BYTES:
        return {}, text
    meta: dict[str, str] = {}
    for line in header_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1].isspace():
            continue  # indented: a nested/continuation value, not a top-level key
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        if key in meta:
            return {}, text  # duplicate key: refuse the whole header
        meta[key] = value.strip()
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
        if skill_md.stat().st_size > _MAX_SKILL_BYTES:
            return None  # an oversized bundle is refused before it is read (BL-057)
        text = skill_md.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # A missing/unreadable file or non-UTF-8 bytes is a load failure, not a
        # crash: the decode boundary is part of the loader contract (BL-057).
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
