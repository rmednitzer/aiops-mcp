"""Tamper-evident evidence over the audit log (BL-011, ADR-0008).

Layers on top of the per-entry hash chain in `praxis.execution.audit`: a periodic
Merkle root (RFC 6962 domain separation), RFC 3161 stamping of the root (fail-closed
verify; LocalStamper default, real TSA behind an optional backend), checkpoint
chaining, and a session header binding the server-binary hash into the trail.
"""

from __future__ import annotations

from praxis.audit.evidence import (
    EvidenceScheduler,
    EvidenceVerifyResult,
    MerkleCheckpoint,
    make_checkpoint,
    verify_evidence,
    write_anchor,
)
from praxis.audit.merkle import merkle_root, merkle_root_hex
from praxis.audit.rfc3161 import (
    LocalStamper,
    Rfc3161Stamper,
    Stamper,
    StampError,
    select_stamper,
)
from praxis.audit.session import SessionHeader, bind_session, server_binary_hash, session_header

__all__ = [
    "EvidenceScheduler",
    "EvidenceVerifyResult",
    "LocalStamper",
    "MerkleCheckpoint",
    "Rfc3161Stamper",
    "SessionHeader",
    "StampError",
    "Stamper",
    "bind_session",
    "make_checkpoint",
    "merkle_root",
    "merkle_root_hex",
    "select_stamper",
    "server_binary_hash",
    "session_header",
    "verify_evidence",
    "write_anchor",
]
