"""Governance-as-code: the machine-checkable compliance catalog (BL-031, ADR-0021).

``catalog`` holds the pydantic model (the single source of truth for the published
JSON Schema, ADR-0014); ``validate`` holds the bidirectional cross-reference rules
that ``scripts/validate_compliance.py`` runs in CI. The catalog data lives in
``docs/governance/compliance-controls.json`` and projects the STPA security
constraints (``docs/stpa/07-security-constraints.md``) and the prose compliance map
(``docs/governance/compliance-map.md``) into a form CI can verify against the code.
"""

from __future__ import annotations

from praxis.governance.catalog import (
    ComplianceCatalog,
    ComplianceControl,
    RegulatoryRef,
    load_catalog,
)
from praxis.governance.validate import validate_catalog

__all__ = [
    "ComplianceCatalog",
    "ComplianceControl",
    "RegulatoryRef",
    "load_catalog",
    "validate_catalog",
]
