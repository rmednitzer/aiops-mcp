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
import socket
import sys
import threading
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol, TextIO

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


def _stderr_note(message: str) -> None:
    """Best-effort operator-visible note on stderr; never raises (invariant 3)."""
    with suppress(Exception):
        print(f"[praxis.audit] {message}", file=sys.stderr)


class AuditSink(Protocol):
    """A secondary destination for canonical audit lines (BL-100, ADR-0037).

    ``emit`` receives the same canonical JSON line written to the primary file and
    must be fast and non-blocking (a datagram, not a blocking stream). A sink may
    raise on failure; ``MultiSink`` contains it so one failing sink can never
    silence the others. Secondary sinks are best-effort forwards: the append-only
    hash-chained file stays the authoritative, tamper-evident source of truth
    (ADR-0008), so a secondary is never required for an audited run to proceed.
    """

    name: str

    def emit(self, line: str) -> None: ...

    def close(self) -> None: ...


class MultiSink:
    """Fan one audit line out to several secondary sinks with per-sink failure
    containment (the BL fan-out class from ``skills.dispatch`` applied to the audit
    write side; BL-100, ADR-0037).

    A sink whose ``emit`` raises ``Exception`` is reported once and skipped, so one
    failing sink can never silence the others (or the primary file write, which runs
    before this fan-out). ``BaseException`` (such as ``KeyboardInterrupt``) still
    propagates. ``emit`` itself never raises (invariant 3).
    """

    def __init__(self, sinks: Sequence[AuditSink] = ()) -> None:
        self._sinks: tuple[AuditSink, ...] = tuple(sinks)
        # Names of sinks currently in a failure streak, so a persistently down sink
        # is noted once rather than on every record; a later success clears it.
        self._failed: set[str] = set()

    @property
    def sinks(self) -> tuple[AuditSink, ...]:
        return self._sinks

    def emit(self, line: str) -> None:
        for sink in self._sinks:
            try:
                sink.emit(line)
            except Exception:  # noqa: BLE001 - per-sink containment (BL-100); a failing sink must not silence the others
                if sink.name not in self._failed:
                    self._failed.add(sink.name)
                    _stderr_note(f"audit sink {sink.name!r} failed; other sinks unaffected")
                continue
            else:
                self._failed.discard(sink.name)

    def close(self) -> None:
        for sink in self._sinks:
            with suppress(Exception):
                sink.close()


class SyslogAuditSink:
    """Best-effort syslog forward of each audit line (BL-100, ADR-0037).

    A secondary sink for SIEM / journald visibility: it sends the same canonical,
    already-redacted audit line (no output body, never a secret; SEC-9) to a syslog
    endpoint over a datagram socket. ``address`` is a Unix socket path (the default
    ``/dev/log``) when it starts with ``/``, otherwise ``host:port`` for a remote UDP
    collector. The connection is lazy and re-established after a failure, so
    construction never raises and a daemon that starts later is picked up. The file
    sink stays authoritative: syslog may truncate or drop an oversized datagram, and
    any such failure is contained by ``MultiSink``.
    """

    name = "syslog"
    # RFC 3164 priority: facility AUTHPRIV (10) << 3 | severity NOTICE (5).
    _PRIORITY = 10 * 8 + 5

    def __init__(self, address: str = "/dev/log", *, tag: str = "praxis-audit") -> None:
        self._address = address
        self._tag = tag
        self._sock: socket.socket | None = None

    def _connect(self) -> socket.socket:
        if self._address.startswith("/"):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            sock.connect(self._address)
        else:
            host, _, port = self._address.rpartition(":")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((host, int(port)))
        return sock

    def emit(self, line: str) -> None:
        if self._sock is None:
            self._sock = self._connect()  # may raise OSError/ValueError -> contained by MultiSink
        frame = f"<{self._PRIORITY}>{self._tag}: {line}".encode("utf-8", errors="surrogatepass")
        try:
            self._sock.send(frame)
        except OSError:
            # Drop the socket so the next emit reconnects, then re-raise so MultiSink
            # records the failure; the authoritative primary write is unaffected.
            with suppress(OSError):
                self._sock.close()
            self._sock = None
            raise

    def close(self) -> None:
        if self._sock is not None:
            with suppress(OSError):
                self._sock.close()
            self._sock = None


class AuditLogger:
    """The audit writer. A single instance owns one append-only JSONL sink."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        clock: Callable[[], str] = utc_now_iso,
        on_record: Callable[[AuditRecord], None] | None = None,
        extra_sinks: Sequence[AuditSink] = (),
    ) -> None:
        self._clock = clock
        self._path = path
        # Best-effort secondary sinks (BL-100, ADR-0037). The primary append-only file
        # below stays authoritative; these are fanned out after each primary write with
        # per-sink failure containment, so none can affect the file, the hash chain, or
        # each other. Empty by default: the default posture is the single file sink.
        self._secondary = MultiSink(extra_sinks)
        # Optional post-record hook (additive; BL-076: the evidence scheduler).
        # Invoked AFTER the record is written and the lock released; contained,
        # so a failing hook can never lose or block a record (invariant 3).
        self._on_record = on_record
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
        # A degraded logger writes to stderr, not the file, so the hook must not
        # fire: evidence produced over a stale audit file would claim coverage
        # of a log that is no longer receiving records (ADR-0019).
        if self._on_record is not None and not self._degraded:
            try:
                self._on_record(record)
            except Exception as exc:  # noqa: BLE001 - the hook must not break the logger
                with suppress(Exception):
                    print(
                        f"[praxis.audit] post-record hook failed ({exc!r}); the record "
                        "itself is written",
                        file=sys.stderr,
                    )
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
        # Fan out to the best-effort secondary sinks after the authoritative primary
        # write (BL-100). Contained: a failing secondary can never affect the primary
        # write above, the hash chain, or the other sinks; emit never raises.
        self._secondary.emit(line)

    def close(self) -> None:
        # Release the real file if one was ever opened, even after a later degrade
        # (BL-055); never close stderr.
        if self._file is not None:
            try:
                self._file.close()
            except OSError:  # pragma: no cover - defensive
                pass
            self._file = None
        # Release any secondary sinks (sockets); contained, never raises.
        self._secondary.close()


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
