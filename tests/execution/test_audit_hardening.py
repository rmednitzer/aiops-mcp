"""Audit hardening: non-JSON-native args never raise (BL-078); concurrent appends
keep one unbroken chain (BL-029)."""

from __future__ import annotations

import threading
from pathlib import Path

from praxis.execution import AuditLogger, verify_chain
from praxis.execution.patterns import PATTERNS_VERSION


def test_record_never_raises_on_non_json_native_args(tmp_path: Path) -> None:
    # BL-078: a Path, a set, or any non-native value canonicalizes via str()
    # instead of raising out of the logger (logger-never-raises, invariant 3).
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    logger.record(
        tool="collector",
        tier="T0",
        decision="allowed",
        args={"path": Path("/etc/passwd"), "tags": {"a", "b"}},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    result = verify_chain(log)
    assert result.ok is True
    assert result.count == 1


def test_concurrent_records_keep_an_unbroken_chain(tmp_path: Path) -> None:
    # BL-029: payload-build + write + chain-advance are serialised, so threaded
    # writers cannot interleave seq/prev_hash state.
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log)
    per_thread = 50

    def write_many() -> None:
        for i in range(per_thread):
            logger.record(
                tool="collector",
                tier="T0",
                decision="allowed",
                args={"i": i},
                patterns_version=PATTERNS_VERSION,
            )

    threads = [threading.Thread(target=write_many) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    logger.close()
    result = verify_chain(log)
    assert result.ok is True, result.reason
    assert result.count == 4 * per_thread
