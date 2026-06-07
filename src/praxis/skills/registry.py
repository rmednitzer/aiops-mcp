"""Skill registry: discover SKILL.md bundles under a directory (ADR-0010).

Discovery is read-only and code-free: it parses frontmatter only (allow_contract is
False), so an untrusted bundle is inert on load. A malformed bundle is skipped, not
fatal.
"""

from __future__ import annotations

from pathlib import Path

from praxis.skills.manifest import SkillManifest, load_skill


class SkillRegistry:
    def __init__(self, manifests: list[SkillManifest] | None = None) -> None:
        self._manifests: list[SkillManifest] = manifests or []

    @classmethod
    def discover(cls, skills_dir: Path) -> SkillRegistry:
        manifests: list[SkillManifest] = []
        if skills_dir.is_dir():
            for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
                manifest = load_skill(skill_md, allow_contract=False)
                if manifest is not None:
                    manifests.append(manifest)
        return cls(manifests)

    def all(self) -> list[SkillManifest]:
        return list(self._manifests)

    def by_kind(self, kind: str) -> list[SkillManifest]:
        return [m for m in self._manifests if m.kind == kind]

    def get(self, name: str) -> SkillManifest | None:
        for manifest in self._manifests:
            if manifest.name == name:
                return manifest
        return None
