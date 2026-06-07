"""Skill discovery and routing: exact + lexical matchers, per-link containment."""

from __future__ import annotations

from pathlib import Path

import pytest

from praxis.skills import HOST_KNOWLEDGE, TOOL, Match, RoutingChainDispatcher, SkillRegistry
from praxis.skills.manifest import load_skill, parse_frontmatter

_ROOT = Path(__file__).resolve().parents[2]


def _dispatcher() -> RoutingChainDispatcher:
    return RoutingChainDispatcher(SkillRegistry.discover(_ROOT / "skills").all())


def test_discover_finds_all_bundles() -> None:
    names = {m.name for m in SkillRegistry.discover(_ROOT / "skills").all()}
    expected = {
        "fleet-inventory",
        "talos-operations",
        "drift-triage",
        "ssh-hardening",
        "audit-verification",
    }
    assert expected <= names


def test_kinds_are_parsed() -> None:
    registry = SkillRegistry.discover(_ROOT / "skills")
    fleet = registry.get("fleet-inventory")
    talos = registry.get("talos-operations")
    assert fleet is not None and fleet.kind == HOST_KNOWLEDGE
    assert talos is not None and talos.kind == TOOL


def test_exact_name_match_wins() -> None:
    dispatcher = _dispatcher()
    assert dispatcher.best("talos-operations") == "talos-operations"
    assert dispatcher.best("show me the fleet inventory") == "fleet-inventory"


def test_lexical_routing() -> None:
    dispatcher = _dispatcher()
    assert dispatcher.best("verify the audit hash chain") == "audit-verification"


def test_per_link_failure_containment(monkeypatch: pytest.MonkeyPatch) -> None:
    dispatcher = _dispatcher()

    def _boom(_query: str) -> list[Match]:
        raise RuntimeError("matcher exploded")

    monkeypatch.setattr(dispatcher, "_exact", _boom)
    # The lexical matcher still routes; a raising link does not abort the chain.
    assert dispatcher.best("verify the audit hash chain") == "audit-verification"


def test_malformed_bundle_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "SKILL.md").write_text("no frontmatter here", encoding="utf-8")
    assert SkillRegistry.discover(tmp_path).all() == []


def test_load_skill_never_executes_contract(tmp_path: Path) -> None:
    bundle = tmp_path / "s"
    bundle.mkdir()
    (bundle / "SKILL.md").write_text(
        "---\nname: s\ndescription: d\nkind: tool\n---\nbody", encoding="utf-8"
    )
    # allow_contract=True is accepted but never honoured; no code runs on load.
    manifest = load_skill(bundle / "SKILL.md", allow_contract=True)
    assert manifest is not None
    assert manifest.name == "s"


def test_parse_frontmatter_without_block() -> None:
    meta, body = parse_frontmatter("# just markdown\ntext")
    assert meta == {}
    assert "just markdown" in body
