"""Secondary audit-sink fan-out with per-sink failure containment (BL-100, ADR-0037).

The append-only hash-chained file stays authoritative; secondary sinks are best-effort
forwards fanned out through ``MultiSink``, which contains a per-sink ``Exception`` so one
failing sink can never silence the others or the primary write, while ``BaseException``
still propagates (invariant 3).
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from praxis.execution.audit import AuditLogger, MultiSink, SyslogAuditSink, verify_chain
from praxis.execution.patterns import PATTERNS_VERSION


class _RecordingSink:
    """An in-memory secondary sink that records every line it receives."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.lines: list[str] = []

    def emit(self, line: str) -> None:
        self.lines.append(line)

    def close(self) -> None:
        pass


class _FailingSink:
    """A secondary sink whose ``emit`` always raises a contained ``Exception``."""

    def __init__(self, name: str = "bad") -> None:
        self.name = name
        self.calls = 0

    def emit(self, line: str) -> None:
        self.calls += 1
        raise RuntimeError("sink down")

    def close(self) -> None:
        pass


def test_multisink_fans_out_to_every_sink() -> None:
    a, b = _RecordingSink("a"), _RecordingSink("b")
    multi = MultiSink([a, b])
    assert multi.sinks == (a, b)
    multi.emit("line-1")
    multi.emit("line-2")
    assert a.lines == ["line-1", "line-2"]
    assert b.lines == ["line-1", "line-2"]


def test_multisink_contains_per_sink_exception() -> None:
    # The BL-100 core: a failing sink (listed first) must not raise out of emit and must
    # not stop the other sink from receiving the line.
    bad = _FailingSink("bad")
    good = _RecordingSink("good")
    multi = MultiSink([bad, good])
    multi.emit("x")  # must not raise
    multi.emit("y")
    assert good.lines == ["x", "y"]
    assert bad.calls == 2  # it was attempted on every record


def test_multisink_propagates_base_exception() -> None:
    # BaseException (e.g. KeyboardInterrupt) is deliberately NOT contained (BL-100).
    class _Interrupting:
        name = "interrupt"

        def emit(self, line: str) -> None:
            raise KeyboardInterrupt

        def close(self) -> None:
            pass

    multi = MultiSink([_Interrupting()])
    with pytest.raises(KeyboardInterrupt):
        multi.emit("x")


def test_multisink_notes_persistent_failure_once(capsys: pytest.CaptureFixture[str]) -> None:
    # A persistently down sink is noted once per failure streak, not on every record,
    # so a broken secondary cannot flood stderr.
    bad = _FailingSink("bad")
    multi = MultiSink([bad])
    for _ in range(3):
        multi.emit("x")
    notes = [ln for ln in capsys.readouterr().err.splitlines() if "audit sink 'bad' failed" in ln]
    assert len(notes) == 1
    assert bad.calls == 3


def test_logger_fans_out_the_same_line_to_a_secondary(tmp_path: Path) -> None:
    mirror = _RecordingSink("mirror")
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, extra_sinks=[mirror])
    logger.record(
        tool="t",
        tier="T0",
        decision="allowed",
        args={"k": "v"},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    # The secondary received exactly the canonical line the file holds.
    file_line = log.read_text(encoding="utf-8").splitlines()[0]
    assert mirror.lines == [file_line]
    assert verify_chain(log).ok is True


def test_failing_secondary_never_breaks_the_primary_or_chain(tmp_path: Path) -> None:
    # A secondary that always raises must not affect the authoritative file write, the
    # hash chain, or record() (which must not raise) (invariant 3, BL-100).
    bad = _FailingSink("bad")
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, extra_sinks=[bad])
    for i in range(3):
        logger.record(
            tool=f"t{i}",
            tier="T0",
            decision="allowed",
            args={"i": i},
            patterns_version=PATTERNS_VERSION,
        )
    logger.close()
    assert bad.calls == 3
    result = verify_chain(log)
    assert result.ok is True
    assert result.count == 3


def test_syslog_sink_delivers_over_a_unix_datagram_socket(tmp_path: Path) -> None:
    if not hasattr(socket, "AF_UNIX"):  # pragma: no cover - POSIX only
        pytest.skip("AF_UNIX not available on this platform")
    sock_path = tmp_path / "syslog.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(str(sock_path))
    server.settimeout(5)
    try:
        sink = SyslogAuditSink(str(sock_path))
        sink.emit('{"seq":0,"tool":"t"}')
        datagram = server.recvfrom(65536)[0].decode("utf-8")
        sink.close()
    finally:
        server.close()
    assert datagram.startswith(f"<{SyslogAuditSink._PRIORITY}>")
    assert "praxis-audit:" in datagram
    assert '{"seq":0,"tool":"t"}' in datagram


def test_syslog_sink_delivers_over_udp() -> None:
    # The remote `host:port` form: parse, connect, and deliver over a UDP datagram.
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(5)
    port = server.getsockname()[1]
    try:
        sink = SyslogAuditSink(f"127.0.0.1:{port}")
        sink.emit('{"seq":1,"tool":"u"}')
        datagram = server.recvfrom(65536)[0].decode("utf-8")
        sink.close()
    finally:
        server.close()
    assert datagram.startswith(f"<{SyslogAuditSink._PRIORITY}>")
    assert '{"seq":1,"tool":"u"}' in datagram


def test_syslog_sink_resets_and_reraises_on_send_failure(tmp_path: Path) -> None:
    # A send failure after a good connection (e.g. the daemon restarted) must drop the
    # socket so the next emit reconnects, and re-raise so MultiSink records it.
    if not hasattr(socket, "AF_UNIX"):  # pragma: no cover - POSIX only
        pytest.skip("AF_UNIX not available on this platform")
    sock_path = tmp_path / "syslog.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(str(sock_path))
    try:
        sink = SyslogAuditSink(str(sock_path))
        sink.emit("first")  # connects and sends
        assert sink._sock is not None
        sink._sock.close()  # force the next send to fail on a closed descriptor
        with pytest.raises(OSError):
            sink.emit("second")
        assert sink._sock is None  # reset, so a later emit reconnects
    finally:
        server.close()


def test_syslog_sink_failure_is_contained_in_the_logger(tmp_path: Path) -> None:
    # A syslog endpoint that does not exist must be contained: the record still reaches
    # the file, record() does not raise, and the chain verifies (BL-100).
    missing = tmp_path / "absent.sock"
    log = tmp_path / "audit.jsonl"
    logger = AuditLogger(log, extra_sinks=[SyslogAuditSink(str(missing))])
    logger.record(
        tool="t",
        tier="T0",
        decision="allowed",
        args={},
        patterns_version=PATTERNS_VERSION,
    )
    logger.close()
    assert verify_chain(log).ok is True
    assert log.read_text(encoding="utf-8").strip()  # the record reached the file
