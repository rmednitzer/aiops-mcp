"""Session header: a stable server-binary hash bound into the audit trail."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from praxis.audit import bind_session, server_binary_hash, session_header
from praxis.execution.audit import AuditLogger


def test_binary_hash_is_stable_hex() -> None:
    first = server_binary_hash()
    assert len(first) == 64
    assert all(c in "0123456789abcdef" for c in first)
    assert first == server_binary_hash()  # deterministic across calls


def test_session_header_fields() -> None:
    header = session_header()
    assert header.binary_sha256 == server_binary_hash()
    assert header.patterns_version >= 1
    assert header.started_at.endswith("Z")


def test_bind_session_writes_provenance_record(tmp_path: Path) -> None:
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit)
    record = bind_session(logger)
    logger.close()
    assert record.decision == "session"
    first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert first["args"]["binary_sha256"] == server_binary_hash()
    # Without an explicit policy the record shape is unchanged (additive default).
    assert "audit_retention_days" not in first["args"]


def test_bind_session_binds_retention_policy(tmp_path: Path) -> None:
    # BL-035: the declared retention tiers are written into the first audit record,
    # so the retention in force is part of the tamper-evident provenance trail.
    audit = tmp_path / "audit.jsonl"
    logger = AuditLogger(audit)
    retention = {"audit_retention_days": 365, "evidence_retention_days": 0}
    bind_session(logger, retention=retention)
    logger.close()
    first = json.loads(audit.read_text(encoding="utf-8").splitlines()[0])
    assert first["args"]["audit_retention_days"] == 365
    assert first["args"]["evidence_retention_days"] == 0  # 0 = retain indefinitely
    # The provenance fields are still present alongside the retention tiers.
    assert first["args"]["binary_sha256"] == server_binary_hash()


def test_bind_session_rejects_provenance_key_collision(tmp_path: Path) -> None:
    # The session record is the provenance root: a retention key must not shadow a
    # provenance field. A collision is refused, not silently overwriting the binding.
    logger = AuditLogger(tmp_path / "audit.jsonl")
    with pytest.raises(ValueError, match="collide"):
        bind_session(logger, retention={"binary_sha256": 1})
    logger.close()
