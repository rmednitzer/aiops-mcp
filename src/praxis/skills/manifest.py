"""Skill manifests and a minimal SKILL.md frontmatter parser (ADR-0010, ADR-0014).

A skill is a bundle: ``SKILL.md`` with simple ``key: value`` frontmatter (name,
description, kind, optional inputs/outputs) plus optional ``references/``. The
frontmatter is split by a hardened parser (exact fence, size caps, no indented or
duplicate keys) and then validated through the ``SkillFrontmatter`` pydantic model,
which is also the single source of truth for the published JSON Schema. Untrusted
bundles are loaded with ``allow_contract=False``: this loader never imports or
executes bundle code.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

HOST_KNOWLEDGE = "host-knowledge"
TOOL = "tool"
SkillKind = Literal["host-knowledge", "tool"]
KINDS = frozenset(get_args(SkillKind))

# A SKILL.md is a small header plus prose. These caps defend the parser against a
# crafted or runaway bundle without affecting any legitimate skill (BL-057).
_MAX_SKILL_BYTES = 1 * 1024 * 1024
_MAX_FRONTMATTER_BYTES = 64 * 1024


class SkillFrontmatter(BaseModel):
    """The validated SKILL.md frontmatter contract (and the published schema source).

    Unknown frontmatter keys are ignored (a bundle may carry extra metadata) and
    string values are whitespace-stripped, matching the loader's prior behaviour.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True, title="SkillManifest")

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    kind: SkillKind
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()

    @field_validator("inputs", "outputs", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        # Frontmatter carries inputs/outputs as a comma-separated string.
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value


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
    try:
        front = SkillFrontmatter.model_validate(meta)
    except ValidationError:
        # Missing/invalid required fields (name, description, kind) are a load
        # failure, surfaced as None rather than a raised exception.
        return None
    return SkillManifest(
        name=front.name,
        description=front.description,
        kind=front.kind,
        path=str(skill_md.parent),
        inputs=front.inputs,
        outputs=front.outputs,
    )
