"""Skills (BL-010, ADR-0010): host-knowledge ("what is") and tool ("how to operate")
bundles, a code-free registry (untrusted bundles load inert), and a routing-chain
dispatcher with per-link failure containment. Dispatch quality is regression-gated
by the P@1/MRR eval (`make eval`).
"""

from __future__ import annotations

from praxis.skills.dispatch import Match, RoutingChainDispatcher
from praxis.skills.manifest import HOST_KNOWLEDGE, KINDS, TOOL, SkillManifest, load_skill
from praxis.skills.registry import SkillRegistry

__all__ = [
    "HOST_KNOWLEDGE",
    "KINDS",
    "TOOL",
    "Match",
    "RoutingChainDispatcher",
    "SkillManifest",
    "SkillRegistry",
    "load_skill",
]
