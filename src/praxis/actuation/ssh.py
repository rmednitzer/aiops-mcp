"""SSH/shell actuation adapter. Never targets a Talos host (SEC-5; invariant 5)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar

from praxis.actuation.base import SAFE_TARGET, ActuationAdapter, HostInfo
from praxis.execution.patterns import Tier
from praxis.model.facts import HostType

# A target must begin with an alphanumeric so it can never be parsed as an ssh
# option (a leading-dash host like ``-oProxyCommand=...`` is an option-injection
# vector even with a list argv, because ssh itself parses it). The shared pattern
# lives in ``base.py`` (BL-081 extends it to ansible).
_SAFE_TARGET = SAFE_TARGET

# Enumerated host-key policies (the OpenSSH ``StrictHostKeyChecking`` values we
# permit). ``accept-new`` is Trust-On-First-Use: a previously unseen key is
# recorded, but a CHANGED key (the MITM signature) is refused. ``yes`` is the
# strict mode that refuses any host not already in known_hosts.
_HOST_KEY_POLICIES: frozenset[str] = frozenset({"accept-new", "yes"})


class SSHAdapter(ActuationAdapter):
    name: ClassVar[str] = "ssh"
    # Ubuntu and Windows (OpenSSH) only. Talos is API-only and immutable: there is
    # no shell to SSH into, so it is deliberately excluded (SEC-5).
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.UBUNTU, HostType.WINDOWS})
    # Free-form remote shell floors at T2 (BL-073, ADR-0016): the tier patterns are
    # a denylist that only rounds up, so an arbitrary command they do not recognise
    # must still meet the human gate. T0/T1 convenience never outweighs an
    # unrecognised destructive command running ungated.
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False  # no safe remote dry-run; preview instead
    # accept-new (TOFU) is the secure default for fleet automation: it pins a new
    # host the first time and refuses a changed key thereafter. BatchMode=yes makes
    # any prompt a hard failure instead of a hang, since an MCP call has no TTY
    # (BL-020). Subclass or set these to tighten to "yes" once known_hosts is seeded.
    host_key_policy: ClassVar[str] = "accept-new"
    connect_timeout_s: ClassVar[int] = 10

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        target = host.ssh_alias or host.name
        if not _SAFE_TARGET.match(target):
            raise ValueError(
                f"unsafe ssh target {target!r}: must start alphanumeric and contain only "
                "[A-Za-z0-9._-[]:@] (host-key/option-injection guard, BL-020)"
            )
        if self.host_key_policy not in _HOST_KEY_POLICIES:
            raise ValueError(
                f"host_key_policy must be one of {sorted(_HOST_KEY_POLICIES)}, "
                f"got {self.host_key_policy!r}"
            )
        return [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            f"StrictHostKeyChecking={self.host_key_policy}",
            "-o",
            f"ConnectTimeout={self.connect_timeout_s}",
            target,
            action,
        ]
