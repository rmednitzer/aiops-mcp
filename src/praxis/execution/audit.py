"""Append-only, hash-chained audit log (ADR-0008; SEC-9, SEC-8, invariant 3).

Every record stores ``output_sha256`` and ``output_len`` and NEVER the output
body. Records form a per-entry hash chain: each commits to the previous record's
hash, so any insertion, deletion, or edit breaks the chain at a detectable point
(``verify``). Construction never raises: if the configured sink cannot be opened
the logger degrades to stderr, so a failed audit subsystem can never silently
permit an unaudited run.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TextIO

from praxis.clock import utc_now_iso

GENESIS = "0" * 64
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """One audit entry. Note: there is no output-body field, by design."""

    seq: int
    ts: str
    tool: str
    target: str | None
    tier: str
    decision: str  # "allowed" | "denied" | "error"
    args: dict[str, object]  # already redacted by the caller
    output_sha256: str
    output_len: int
    error: str | None
    patterns_version: int
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _canonical(payload: dict[str, object]) -> str:
    # default=str (BL-078): a non-JSON-native arg value (a Path, an Enum, a
    # datetime) canonicalizes as its str() form instead of raising, so
    # AuditLogger.record can never raise on hostile or unusual arg shapes
    # (logger-never-raises by construction, invariant 3). The written line is
    # produced by this same function, so verification stays consistent.
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def compute_entry_hash(payload: dict[str, object]) -> str:
    """Hash the record payload (all fields except ``entry_hash``)."""
    return sha256_text(_canonical(payload))


class AuditLogger:
    """The audit writer. A single instance owns one append-only JSONL sink."""

    def __init__(self, path: Path | None = None, *, clock: Callable[[], str] = utc_now_iso) -> None:
        self._clock = clock
        self._path = path
        self._seq = 0
        self._prev_hash = GENESIS
        # Serialises payload-build + write + chain-advance so concurrent in-process
        # writers cannot interleave seq/prev_hash state (BL-029). One process owns
        # one audit file: cross-process coordination is the Postgres path.
        self._lock = threading.Lock()
        self._sink: TextIO
        self._file: TextIO | None = None
        self._degraded = False
        # Recover the chain head from an existing file so restarts continue the
        # same chain. Any failure here degrades but never raises (SEC-8).
        if path is not None:
            try:
                self._recover(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._file = self._open_appendonly(path)
                self._sink = self._file
            except OSError as exc:  # pragma: no cover - exercised via stderr test
                self._degrade(f"audit sink unavailable ({exc}); degraded to stderr")
        else:
            self._sink = sys.stderr

    @staticmethod
    def _open_appendonly(path: Path) -> TextIO:
        """Open the sink append-only (``O_APPEND``) and owner-only (``0o600``).

        ``O_APPEND`` at the OS level keeps the writer compatible with an append-only
        hardened file (``chattr +a``). The explicit ``0o600`` mode, plus a
        best-effort chmod of any pre-existing file, keeps the audit log, which holds
        redacted parameters, unreadable by other local users (SEC-9).
        """
        fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        handle = os.fdopen(fd, "a", encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover - best effort on a pre-existing file
            pass
        return handle

    def _degrade(self, message: str) -> None:
        # Writes go to stderr from here on; ``_file`` (if any) is kept only so
        # ``close`` can release it. The sink is never silently reopened (BL-055).
        self._degraded = True
        self._sink = sys.stderr
        print(f"[praxis.audit] {message}", file=sys.stderr)

    def _recover(self, path: Path) -> None:
        if not path.exists():
            return
        last_line = ""
        try:
            with path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    stripped = line.strip()
                    if stripped:
                        last_line = stripped
        except UnicodeDecodeError:
            # A non-UTF-8 (corrupted or poisoned) audit file: treat it as a corrupt
            # tail and resume at genesis (visible seam), the same as an unparseable
            # JSON tail. UnicodeDecodeError is a ValueError, not an OSError, so it
            # would otherwise escape __init__ and break "construction never raises"
            # (SEC-8, invariant 3).
            self._seq = 0
            self._prev_hash = GENESIS
            return
        if not last_line:
            return
        try:
            last = json.loads(last_line)
            self._seq = int(last["seq"]) + 1
            self._prev_hash = str(last["entry_hash"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # Corrupt tail: do not raise, do not truncate, and do NOT drop the sink.
            # Resume at genesis (seq 0, GENESIS prev) and keep writing to the file:
            # the seq reset is a visible seam that verify_chain reports (the security
            # signal), whereas degrading to stderr would lose the record entirely,
            # which is worse (BL-055).
            self._seq = 0
            self._prev_hash = GENESIS

    @property
    def degraded(self) -> bool:
        return self._degraded

    @property
    def path(self) -> Path | None:
        return self._path

    def record(
        self,
        *,
        tool: str,
        tier: str,
        decision: str,
        args: dict[str, object],
        output_sha256: str = EMPTY_SHA256,
        output_len: int = 0,
        target: str | None = None,
        error: str | None = None,
        patterns_version: int,
    ) -> AuditRecord:
        """Append one record and advance the chain. Never raises on write."""
        with self._lock:
            payload: dict[str, object] = {
                "seq": self._seq,
                "ts": self._clock(),
                "tool": tool,
                "target": target,
                "tier": tier,
                "decision": decision,
                "args": args,
                "output_sha256": output_sha256,
                "output_len": output_len,
                "error": error,
                "patterns_version": patterns_version,
                "prev_hash": self._prev_hash,
            }
            # Normalize ONCE before hashing (BL-094): a non-native arg value is
            # rendered by ``default=str`` here and again when ``_write``
            # canonicalizes the ``asdict()`` deep copy, and str() of a copy is
            # not guaranteed to match (a deepcopied set may iterate in a
            # different order), which would write a line that fails its own
            # entry_hash. After this round-trip every value is JSON-native, so
            # the hash and the written line derive from one rendering.
            payload = json.loads(_canonical(payload))
            entry_hash = compute_entry_hash(payload)
            record = AuditRecord(entry_hash=entry_hash, **payload)  # type: ignore[arg-type]
            self._write(record)
            self._seq += 1
            self._prev_hash = entry_hash
            return record

    def _write(self, record: AuditRecord) -> None:
        line = _canonical(record.to_dict())
        try:
            self._sink.write(line + "\n")
            self._sink.flush()
        except (OSError, ValueError):  # pragma: no cover - defensive
            if not self._degraded:
                self._degrade("audit write failed; degraded to stderr")
                try:
                    self._sink.write(line + "\n")
                    self._sink.flush()
                except OSError:
                    pass

    def close(self) -> None:
        # Release the real file if one was ever opened, even after a later degrade
        # (BL-055); never close stderr.
        if self._file is not None:
            try:
                self._file.close()
            except OSError:  # pragma: no cover - defensive
                pass
            self._file = None


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    broken_at: int | None
    reason: str | None


def verify_chain(path: Path) -> VerifyResult:
    """Recompute the hash chain of a log file and report the first break."""
    prev = GENESIS
    count = 0
    expected_seq = 0
    try:
        lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except OSError as exc:
        return VerifyResult(ok=False, count=0, broken_at=None, reason=str(exc))
    for line in lines:
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            return VerifyResult(ok=False, count=count, broken_at=count, reason=f"bad json: {exc}")
        stored_hash = rec.get("entry_hash")
        payload = {k: v for k, v in rec.items() if k != "entry_hash"}
        if rec.get("prev_hash") != prev:
            return VerifyResult(ok=False, count=count, broken_at=count, reason="prev_hash mismatch")
        if rec.get("seq") != expected_seq:
            return VerifyResult(ok=False, count=count, broken_at=count, reason="seq discontinuity")
        if compute_entry_hash(payload) != stored_hash:
            return VerifyResult(
                ok=False, count=count, broken_at=count, reason="entry_hash mismatch"
            )
        prev = str(stored_hash)
        count += 1
        expected_seq += 1
    return VerifyResult(ok=True, count=count, broken_at=None, reason=None)
