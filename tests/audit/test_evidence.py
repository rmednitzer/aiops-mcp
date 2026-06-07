"""Evidence checkpoints: verify ok, detect tamper, fail-closed on bad tokens."""

from __future__ import annotations

import json
from pathlib import Path

from praxis.audit import make_checkpoint, verify_evidence
from praxis.audit.rfc3161 import Rfc3161Stamper
from praxis.execution.audit import AuditLogger


def _log(tmp_path: Path, n: int = 3) -> Path:
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    for i in range(n):
        logger.record(
            tool=f"t{i}", tier="T0", decision="allowed", args={"i": i}, patterns_version=1
        )
    logger.close()
    return path


def test_checkpoint_and_verify_ok(tmp_path: Path) -> None:
    audit = _log(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)
    result = verify_evidence(audit, evidence)
    assert result.ok is True
    assert result.checkpoints == 1


def test_two_checkpoints_chain(tmp_path: Path) -> None:
    audit = _log(tmp_path, n=2)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)
    # more records, then a second checkpoint
    logger = AuditLogger(audit)
    logger.record(tool="more", tier="T0", decision="allowed", args={}, patterns_version=1)
    logger.close()
    make_checkpoint(audit, evidence)
    result = verify_evidence(audit, evidence)
    assert result.ok is True
    assert result.checkpoints == 2


def test_verify_detects_log_tamper(tmp_path: Path) -> None:
    audit = _log(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)
    lines = audit.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["tool"] = "evil"
    lines[1] = json.dumps(record)
    audit.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert verify_evidence(audit, evidence).ok is False


def test_verify_detects_checkpoint_tamper(tmp_path: Path) -> None:
    audit = _log(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)
    cp = json.loads(evidence.read_text(encoding="utf-8").splitlines()[0])
    cp["root_sha256"] = "0" * 64
    evidence.write_text(json.dumps(cp) + "\n", encoding="utf-8")
    assert verify_evidence(audit, evidence).ok is False


def test_verify_is_fail_closed_on_invalid_token(tmp_path: Path) -> None:
    audit = _log(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)  # stamped by LocalStamper
    # An Rfc3161Stamper.verify returns False for these local tokens: fail-closed.
    result = verify_evidence(audit, evidence, stamper=Rfc3161Stamper("https://tsa.example"))
    assert result.ok is False
    assert result.reason is not None
    assert "token" in result.reason


def test_verify_rejects_undercovering_checkpoint(tmp_path: Path) -> None:
    # A checkpoint taken over an empty log, then records appended: the checkpoint
    # now under-covers the log. Fail-closed: the uncovered tail is detected so a
    # forged tree_size cannot hide later records (BL-037). This was reproduced:
    # before the fix a tree_size=0 checkpoint verified ok over a non-empty log.
    audit = tmp_path / "audit.jsonl"
    AuditLogger(audit).close()  # an empty log: tree_size 0
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)
    logger = AuditLogger(audit)
    for i in range(3):
        logger.record(tool=f"t{i}", tier="T0", decision="allowed", args={}, patterns_version=1)
    logger.close()
    result = verify_evidence(audit, evidence)
    assert result.ok is False
    assert result.reason is not None
    assert "cover" in result.reason


def test_verify_rejects_checkpoint_claiming_more_than_the_log(tmp_path: Path) -> None:
    # A checkpoint may not claim more lines than the log holds (BL-037).
    audit = _log(tmp_path, n=3)
    evidence = tmp_path / "evidence.jsonl"
    make_checkpoint(audit, evidence)  # tree_size 3
    lines = audit.read_text(encoding="utf-8").splitlines()
    audit.write_text(lines[0] + "\n", encoding="utf-8")  # truncate to one record
    result = verify_evidence(audit, evidence)
    assert result.ok is False
    assert result.reason is not None
    assert "range" in result.reason


def test_verify_fail_closed_on_malformed_evidence(tmp_path: Path) -> None:
    # An unreadable evidence line returns ok=False, never raises (BL-037).
    audit = _log(tmp_path)
    evidence = tmp_path / "evidence.jsonl"
    evidence.write_text("this is not json\n", encoding="utf-8")
    result = verify_evidence(audit, evidence)
    assert result.ok is False
    assert result.reason is not None
    assert "unreadable" in result.reason
