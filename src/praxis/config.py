"""Configuration: PRAXIS_-prefixed environment, bound once at import (ADR-0006).

stdio is the default transport. HTTP is opt-in and fails closed: it requires a
token AND, for any non-loopback bind, an explicit literal opt-in. The transport
guard (`validate_transport`) enforces this before the server binds anything.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from praxis.execution.policy import Mode

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
ALLOW_ANY_TOKEN = "yes-i-understand-the-risk"  # noqa: S105 - a public opt-in literal, not a secret


class TransportError(Exception):
    """Raised when a transport configuration is unsafe. Fails closed."""


@dataclass(frozen=True)
class Config:
    transport: str = "stdio"
    http_host: str = "127.0.0.1"
    http_port: int = 8765
    http_token: str | None = None
    allow_any: bool = False
    allow_restricted: bool = True
    store_dsn: str | None = None
    mode: Mode = Mode.GUARDED
    audit_path: str | None = None

    @property
    def http_is_loopback(self) -> bool:
        return self.http_host in LOOPBACK_HOSTS


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


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

    return Config(
        transport=transport,
        http_host=get("HTTP_HOST", "127.0.0.1") or "127.0.0.1",
        http_port=int(get("HTTP_PORT", "8765") or "8765"),
        http_token=get("HTTP_TOKEN"),
        allow_any=(get("HTTP_ALLOW_ANY") == ALLOW_ANY_TOKEN),
        allow_restricted=_truthy(get("ALLOW_RESTRICTED", restricted_default)),
        store_dsn=get("STORE_DSN"),
        mode=mode,
        audit_path=get("AUDIT_PATH"),
    )


def validate_transport(config: Config) -> None:
    """Enforce the transport invariants before binding. Fails closed (SEC-7)."""
    if config.transport == "stdio":
        return
    if config.transport != "http":
        raise TransportError(f"unknown transport: {config.transport!r}")
    if not config.http_token:
        raise TransportError("HTTP transport requires PRAXIS_HTTP_TOKEN (no token, no bind)")
    if not config.http_is_loopback and not config.allow_any:
        raise TransportError(
            "non-loopback HTTP bind requires PRAXIS_HTTP_ALLOW_ANY="
            f"{ALLOW_ANY_TOKEN!r}; the token alone does not authorize off-host exposure"
        )


# Bound once at import (ADR-0006). Tests construct Config directly or call
# load_config with an explicit env.
CONFIG = load_config()
