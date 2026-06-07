"""Session header: a stable server-binary hash bound into the audit trail."""

from __future__ import annotations

import json
from pathlib import Path

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
