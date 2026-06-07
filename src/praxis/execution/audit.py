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
import sys
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
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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
        self._sink: TextIO
        self._degraded = False
        # Recover the chain head from an existing file so restarts continue the
        # same chain. Any failure here degrades but never raises (SEC-8).
        if path is not None:
            try:
                self._recover(path)
                path.parent.mkdir(parents=True, exist_ok=True)
                self._sink = path.open("a", encoding="utf-8")
            except OSError as exc:  # pragma: no cover - exercised via stderr test
                self._degrade(f"audit sink unavailable ({exc}); degraded to stderr")
        else:
            self._sink = sys.stderr

    def _degrade(self, message: str) -> None:
        self._degraded = True
        self._sink = sys.stderr
        print(f"[praxis.audit] {message}", file=sys.stderr)

    def _recover(self, path: Path) -> None:
        if not path.exists():
            return
        last_line = ""
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    last_line = stripped
        if not last_line:
            return
        try:
            last = json.loads(last_line)
            self._seq = int(last["seq"]) + 1
            self._prev_hash = str(last["entry_hash"])
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # Corrupt tail: do not raise, do not truncate. verify() will expose
            # the discontinuity rather than the writer hiding it.
            self._degrade(f"could not recover audit chain head from {path}")

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
        if self._path is not None and not self._degraded:
            try:
                self._sink.close()
            except OSError:  # pragma: no cover - defensive
                pass


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
