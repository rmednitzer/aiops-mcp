"""Runtime evidence production (BL-076) and the anchor high-water mark (BL-050).

The scheduler is the AuditLogger's post-record hook: every N records it
checkpoints the log, finalize covers the tail, and each checkpoint head is
appended to the anchor file. The anchor is what detects the one attack the
per-file checks cannot: rewriting BOTH the audit log and the evidence file to a
shorter consistent history.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from praxis.audit import EvidenceScheduler, verify_evidence
from praxis.config import Config, load_config
from praxis.execution.audit import AuditLogger
from praxis.execution.patterns import PATTERNS_VERSION
from praxis.server import build_context


def _wired_logger(
    tmp_path: Path, *, every: int, anchor: bool = True
) -> tuple[AuditLogger, EvidenceScheduler, Path, Path, Path]:
    audit = tmp_path / "audit.jsonl"
    evidence = tmp_path / "audit.evidence.jsonl"
    anchor_path = tmp_path / "anchor.jsonl"
    scheduler = EvidenceScheduler(
        audit, evidence, every=every, anchor_path=anchor_path if anchor else None
    )
    logger = AuditLogger(audit, on_record=scheduler.on_record)
    return logger, scheduler, audit, evidence, anchor_path


def _record(logger: AuditLogger, n: int) -> None:
    for i in range(n):
        logger.record(
            tool=f"t{i}",
            tier="T0",
            decision="allowed",
            args={"i": i},
            patterns_version=PATTERNS_VERSION,
        )


def test_scheduler_checkpoints_every_n_records(tmp_path: Path) -> None:
    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=2)
    _record(logger, 5)
    logger.close()
    # 5 records at every=2: checkpoints after records 2 and 4; the 5th is tail.
    assert len(evidence.read_text(encoding="utf-8").splitlines()) == 2
    scheduler.finalize()
    assert len(evidence.read_text(encoding="utf-8").splitlines()) == 3
    result = verify_evidence(audit, evidence, anchor_path=anchor)
    assert result.ok is True, result.reason
    assert result.checkpoints == 3


def test_finalize_without_pending_records_is_a_no_op(tmp_path: Path) -> None:
    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=2)
    _record(logger, 2)
    logger.close()
    scheduler.finalize()
    scheduler.finalize()
    assert len(evidence.read_text(encoding="utf-8").splitlines()) == 1
    assert verify_evidence(audit, evidence, anchor_path=anchor).ok is True


def test_scheduler_failure_never_breaks_the_audited_record(tmp_path: Path) -> None:
    # The evidence sink is unwritable (a directory); records must still land and
    # the logger must not raise (contained, the hash chain is the primary record).
    audit = tmp_path / "audit.jsonl"
    bad_evidence = tmp_path / "evidence-as-dir"
    bad_evidence.mkdir()
    scheduler = EvidenceScheduler(audit, bad_evidence, every=1)
    logger = AuditLogger(audit, on_record=scheduler.on_record)
    _record(logger, 3)
    logger.close()
    assert len(audit.read_text(encoding="utf-8").splitlines()) == 3


def test_anchor_detects_consistent_truncation_of_log_and_evidence(tmp_path: Path) -> None:
    # The BL-050 attack: rewrite BOTH files to a shorter, internally consistent
    # history. Without the anchor this verifies; with it, it fails.
    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=2)
    _record(logger, 4)
    logger.close()
    long_audit = audit.read_text(encoding="utf-8").splitlines()
    long_evidence = evidence.read_text(encoding="utf-8").splitlines()
    assert len(long_evidence) == 2

    # Replay the first checkpoint era only: two records, one checkpoint.
    audit.write_text("\n".join(long_audit[:2]) + "\n", encoding="utf-8")
    evidence.write_text(long_evidence[0] + "\n", encoding="utf-8")
    assert verify_evidence(audit, evidence).ok is True  # the gap the anchor closes
    result = verify_evidence(audit, evidence, anchor_path=anchor)
    assert result.ok is False
    assert result.reason is not None
    assert "high-water" in result.reason


def test_anchor_detects_rewritten_evidence_at_same_seq(tmp_path: Path) -> None:
    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=2)
    _record(logger, 2)
    logger.close()
    # Forge a fully consistent log+evidence pair from scratch at the same seq.
    audit.write_text("", encoding="utf-8")
    evidence.unlink()
    forged_logger = AuditLogger(audit)
    forged_logger.record(
        tool="forged", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    forged_logger.close()
    from praxis.audit import make_checkpoint

    make_checkpoint(audit, evidence)
    assert verify_evidence(audit, evidence).ok is True
    result = verify_evidence(audit, evidence, anchor_path=anchor)
    assert result.ok is False
    assert result.reason is not None
    assert "mismatch" in result.reason


def test_missing_or_empty_anchor_fails_closed_only_with_checkpoints(tmp_path: Path) -> None:
    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=2, anchor=False)
    _record(logger, 2)
    logger.close()
    ghost = tmp_path / "never-written.jsonl"
    result = verify_evidence(audit, evidence, anchor_path=ghost)
    assert result.ok is False
    assert result.reason is not None and "missing" in result.reason
    ghost.touch()
    result = verify_evidence(audit, evidence, anchor_path=ghost)
    assert result.ok is False
    assert result.reason is not None and "empty" in result.reason
    # Genesis: no checkpoints, no anchor lines -> vacuously consistent.
    fresh_audit = tmp_path / "fresh.jsonl"
    AuditLogger(fresh_audit).close()
    assert verify_evidence(fresh_audit, tmp_path / "no-evidence.jsonl", anchor_path=ghost).ok


def test_build_context_wires_runtime_evidence(tmp_path: Path) -> None:
    # BL-076 end to end through the server context: the session-header record
    # plus tool records trigger checkpoints; finalize covers the tail; the
    # derived evidence path and the anchor verify together.
    audit = tmp_path / "audit.jsonl"
    anchor = tmp_path / "anchor.jsonl"
    cfg = Config(
        transport="stdio",
        audit_path=str(audit),
        evidence_every=2,
        anchor_path=str(anchor),
    )
    ctx = build_context(cfg)
    assert ctx.evidence is not None
    ctx.execution.audit.record(
        tool="t", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    ctx.evidence.finalize()
    ctx.execution.audit.close()
    evidence = audit.with_suffix(".evidence.jsonl")
    assert evidence.exists() and anchor.exists()
    result = verify_evidence(audit, evidence, anchor_path=anchor)
    assert result.ok is True, result.reason


def test_ingest_raw_hash_is_merkle_committed(tmp_path: Path) -> None:
    # BL-030: the ingest audit record carries raw_sha256 (BL-085), so once
    # checkpoints cover the log the collected snapshot's hash is committed
    # under a verified Merkle root.
    from praxis.execution.audit import sha256_text
    from praxis.server import build_registry

    audit = tmp_path / "audit.jsonl"
    cfg = Config(transport="stdio", audit_path=str(audit), evidence_every=1)
    ctx = build_context(cfg)
    raw = "kernel=6.18.5\nhostname=axiom\n"
    build_registry().call(
        "ingest_observation",
        {"collector": "probe", "subject": "host:axiom", "raw": raw},
        ctx,
    )
    assert ctx.evidence is not None
    ctx.evidence.finalize()
    ctx.execution.audit.close()
    evidence = audit.with_suffix(".evidence.jsonl")
    result = verify_evidence(audit, evidence)
    assert result.ok is True, result.reason
    covered = audit.read_text(encoding="utf-8")
    assert sha256_text(raw) in covered


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 64), ("abc", 64), ("0", 0), ("-3", 64), ("7", 7)],
)
def test_evidence_every_parses_fail_safe(raw: str | None, expected: int) -> None:
    # Parse-only: load_config never touches the filesystem for these values.
    env = {"PRAXIS_AUDIT_PATH": "/var/lib/praxis/audit.jsonl"}
    if raw is not None:
        env["PRAXIS_EVIDENCE_EVERY"] = raw
    cfg = load_config(env)
    assert cfg.evidence_every == expected


def test_anchor_file_is_owner_only(tmp_path: Path) -> None:
    import stat

    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=1)
    _record(logger, 1)
    logger.close()
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o600
    # The anchor grows append-only with one head per checkpoint.
    _record_more = AuditLogger(audit, on_record=scheduler.on_record)
    _record(_record_more, 1)
    _record_more.close()
    heads = [json.loads(ln) for ln in anchor.read_text(encoding="utf-8").splitlines()]
    assert [h["seq"] for h in heads] == [0, 1]


def test_degraded_logger_produces_no_evidence(tmp_path: Path) -> None:
    # The documented guarantee: records that go to stderr (degraded sink) must
    # not drive checkpoints, or the evidence would claim coverage of a log that
    # is no longer receiving records (ADR-0019).
    audit_as_dir = tmp_path / "audit.jsonl"
    audit_as_dir.mkdir()  # the file sink cannot open: the logger degrades
    evidence = tmp_path / "evidence.jsonl"
    scheduler = EvidenceScheduler(audit_as_dir, evidence, every=1)
    logger = AuditLogger(audit_as_dir, on_record=scheduler.on_record)
    assert logger.degraded is True
    logger.record(
        tool="t", tier="T0", decision="allowed", args={}, patterns_version=PATTERNS_VERSION
    )
    logger.close()
    assert not evidence.exists()


def test_pre_existing_anchor_is_repermissioned(tmp_path: Path) -> None:
    import stat

    logger, scheduler, audit, evidence, anchor = _wired_logger(tmp_path, every=1)
    anchor.touch(mode=0o644)
    anchor.chmod(0o644)
    _record(logger, 1)
    logger.close()
    assert stat.S_IMODE(anchor.stat().st_mode) == 0o600
