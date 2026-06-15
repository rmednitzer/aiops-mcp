"""Configuration: PRAXIS_-prefixed environment, bound once at import (ADR-0006).

stdio is the default transport. HTTP is opt-in and fails closed: it requires a
token AND, for any non-loopback bind, an explicit literal opt-in. The transport
guard (`validate_transport`) enforces this before the server binds anything.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict

from praxis.execution.policy import Mode

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ALLOW_ANY_TOKEN = "yes-i-understand-the-risk"  # noqa: S105 - a public opt-in literal, not a secret
# Default retention tier for the audit and evidence trails (BL-035): one year, a
# conservative floor for incident reconstruction under NIS2 Art. 23 / ISO 27001
# A.8.15. Operators tune it per their regime; 0 retains indefinitely.
DEFAULT_RETENTION_DAYS = 365


class TransportError(Exception):
    """Raised when a transport configuration is unsafe. Fails closed."""


class Config(BaseModel):
    """The validated server configuration (ADR-0006, ADR-0014).

    A frozen, typed model: ``load_config`` parses the PRAXIS_ environment leniently
    (never raising at import) and constructs this. Deferred safety checks (port range,
    the non-loopback opt-in) stay in ``validate_transport``, the fail-closed gate run
    before any bind, so they are not duplicated as construction-time validators.
    """

    model_config = ConfigDict(frozen=True)

    transport: str = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8765
    http_token: str | None = None
    allow_any: bool = False
    allow_restricted: bool = True
    store_dsn: str | None = None
    mode: Mode = Mode.GUARDED
    audit_path: str | None = None
    # Runtime evidence production (BL-076): with an audit file configured, a
    # Merkle checkpoint is taken every evidence_every records and at orderly
    # shutdown. None evidence_path derives `<audit>.evidence.jsonl`; 0 disables.
    # anchor_path appends each checkpoint head to a separate high-water-mark
    # file (BL-050); point it at a different trust domain than the audit file.
    evidence_path: str | None = None
    evidence_every: int = 64
    anchor_path: str | None = None
    # Documented audit/evidence retention tiers, bound here as the single source of
    # truth (BL-035, ADR-0011/0023). The trail is append-only: the audit hash chain
    # and the evidence/anchor files are never rewritten in place (invariant 4, SEC-9,
    # SEC-10), so these are the DECLARED retention periods that the storage/deploy
    # layer enforces by time-based archival of files older than the tier (WORM or an
    # archive-then-rotate job, never an in-place truncate), not a runtime delete. The
    # policy is bound into the first session audit record so the retention in force is
    # itself part of the tamper-evident trail (NIS2 Art. 23, ISO 27001 A.8.15). Days;
    # 0 means retain indefinitely. The anchor file follows the evidence tier.
    audit_retention_days: int = DEFAULT_RETENTION_DAYS
    evidence_retention_days: int = DEFAULT_RETENTION_DAYS
    # Optional best-effort secondary audit sink (BL-100, ADR-0037): forward each audit
    # line to syslog for SIEM / journald visibility, alongside the authoritative
    # append-only file. A Unix socket path (e.g. `/dev/log`) or `host:port` for a remote
    # UDP collector. None (default) keeps the single file sink unchanged; a failing
    # syslog endpoint is contained and never affects the file write or the hash chain.
    audit_syslog_address: str | None = None
    # Non-forgeable timestamp stamper (BL-095, ADR-0029). With tsa_url set, evidence
    # checkpoints are stamped by an RFC 3161 timestamp authority instead of the
    # forgeable LocalStamper, and tsa_cert_path (the TSA signing certificate, PEM) is
    # required to verify the tokens; selection fails closed if either is missing or the
    # `tsa` extra is absent. Empty leaves the offline LocalStamper default, with OS
    # append-only storage as the documented control (SECURITY.md, ADR-0019).
    tsa_url: str | None = None
    tsa_cert_path: str | None = None
    # Confinement roots for path-based actuation (BL-024, BL-081, BL-105). None refuses
    # the corresponding capability outright: fail closed. tofu_root confines an OpenTofu
    # workspace `-chdir`; with it unset, supplying a chdir is refused.
    playbook_root: str | None = None
    runbook_root: str | None = None
    tofu_root: str | None = None
    # Durable kill-switch sentinel file (BL-075). When set, a trip writes the
    # file, the switch reads as tripped while the file exists, and the stop
    # survives a restart. Restore by removing the file out-of-band.
    kill_switch_path: str | None = None
    # Per-session budget ceilings on the audited path (BL-074). None or 0 means
    # no tracker on that axis; any set axis enables enforcement.
    max_actions: int | None = None
    max_wall_seconds: int | None = None
    # Approval nonce TTL in seconds (BL-072).
    approval_ttl_seconds: int = 600

    @property
    def http_is_loopback(self) -> bool:
        return self.http_host in LOOPBACK_HOSTS

    @property
    def retention_args(self) -> dict[str, int]:
        """The retention tiers as audit-record args (BL-035).

        Bound into the first session audit record so the declared retention is part
        of the tamper-evident provenance (NIS2 Art. 23, ISO 27001 A.8.15). A value of
        0 records as indefinite retention.
        """
        return {
            "audit_retention_days": self.audit_retention_days,
            "evidence_retention_days": self.evidence_retention_days,
        }


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _root_or_none(value: str | None) -> str | None:
    """A confinement root from the environment: empty or whitespace-only means UNSET.

    An actuation confinement root (PRAXIS_PLAYBOOK_ROOT/RUNBOOK_ROOT/TOFU_ROOT) must
    fail closed when not configured. A bare `PRAXIS_*_ROOT=""` would otherwise resolve
    to the current working directory and silently widen confinement, so an empty or
    whitespace value is normalised to None (refuse outright), matching the unset case
    (BL-024/BL-081/BL-105). Whitespace is stripped, as for the HTTP host (BL-067)."""
    if value is None:
        return None
    return value.strip() or None


def _safe_int(value: str | None, default: int) -> int:
    """Parse an int, falling back to ``default`` so import-time config never raises.

    A non-numeric value degrades to the default; an out-of-range numeric value is
    surfaced later by ``validate_transport`` through the fail-closed path."""
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _interval_or_default(value: str | None, default: int) -> int:
    """Parse a record interval where only an explicit ``0`` disables.

    Any misconfiguration, non-numeric or negative, degrades to the default
    interval, never to disabled: a typo must not be able to switch runtime
    evidence off (fail-safe direction; ADR-0019).
    """
    parsed = _safe_int(value, default)
    return parsed if parsed >= 0 else default


def load_config(env: Mapping[str, str] | None = None) -> Config:
    """Read PRAXIS_ environment into a Config. Pure given an explicit ``env``."""
    src = env if env is not None else os.environ

    def get(name: str, default: str | None = None) -> str | None:
        return src.get(f"PRAXIS_{name}", default)

    transport = (get("TRANSPORT", "stdio") or "stdio").lower()
    mode_raw = (get("MODE", "guarded") or "guarded").lower()
    try:
        mode = Mode(mode_raw)
    except ValueError:
        mode = Mode.GUARDED

    # Restricted output is allowed on stdio (local operator) by default, but
    # default-denied over HTTP unless explicitly enabled.
    restricted_default = "true" if transport == "stdio" else "false"

    # Strip stray whitespace so a value like "127.0.0.1\n" is still recognised as
    # loopback by the transport guard; an empty/whitespace host defaults to loopback,
    # the safest bind (BL-060).
    http_host = (get("HTTP_HOST", "127.0.0.1") or "127.0.0.1").strip() or "127.0.0.1"

    def positive_or_none(name: str) -> int | None:
        parsed = _safe_int(get(name), 0)
        return parsed if parsed > 0 else None

    return Config(
        transport=transport,
        http_host=http_host,
        http_port=_safe_int(get("HTTP_PORT", "8765"), 8765),
        http_token=get("HTTP_TOKEN"),
        allow_any=(get("HTTP_ALLOW_ANY") == ALLOW_ANY_TOKEN),
        allow_restricted=_truthy(get("ALLOW_RESTRICTED", restricted_default)),
        store_dsn=get("STORE_DSN"),
        mode=mode,
        audit_path=get("AUDIT_PATH"),
        evidence_path=get("EVIDENCE_PATH"),
        evidence_every=_interval_or_default(get("EVIDENCE_EVERY"), 64),
        anchor_path=get("ANCHOR_PATH"),
        audit_syslog_address=get("AUDIT_SYSLOG_ADDRESS"),
        audit_retention_days=_interval_or_default(
            get("AUDIT_RETENTION_DAYS"), DEFAULT_RETENTION_DAYS
        ),
        evidence_retention_days=_interval_or_default(
            get("EVIDENCE_RETENTION_DAYS"), DEFAULT_RETENTION_DAYS
        ),
        tsa_url=get("TSA_URL"),
        tsa_cert_path=get("TSA_CERT"),
        playbook_root=_root_or_none(get("PLAYBOOK_ROOT")),
        runbook_root=_root_or_none(get("RUNBOOK_ROOT")),
        tofu_root=_root_or_none(get("TOFU_ROOT")),
        kill_switch_path=get("KILL_SWITCH_PATH"),
        max_actions=positive_or_none("MAX_ACTIONS"),
        max_wall_seconds=positive_or_none("MAX_WALL_SECONDS"),
        approval_ttl_seconds=max(1, _safe_int(get("APPROVAL_TTL_SECONDS", "600"), 600)),
    )


def validate_transport(config: Config) -> None:
    """Enforce the transport invariants before binding. Fails closed (SEC-7)."""
    if config.transport == "stdio":
        return
    if config.transport != "http":
        raise TransportError(f"unknown transport: {config.transport!r}")
    if not config.http_token:
        raise TransportError("HTTP transport requires PRAXIS_HTTP_TOKEN (no token, no bind)")
    if not 1 <= config.http_port <= 65535:
        raise TransportError(f"HTTP port out of range (1-65535): {config.http_port}")
    if not config.http_is_loopback and not config.allow_any:
        raise TransportError(
            "non-loopback HTTP bind requires PRAXIS_HTTP_ALLOW_ANY="
            f"{ALLOW_ANY_TOKEN!r}; the token alone does not authorize off-host exposure"
        )


# Bound once at import (ADR-0006). Tests construct Config directly or call
# load_config with an explicit env.
CONFIG = load_config()
