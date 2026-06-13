"""talosctl actuation adapter. The ONLY actuation path for a Talos host (SEC-5).

Talos is API-only and immutable: there is no SSH. Endpoints are the control-plane
IPs talosctl connects to; nodes are the machines a request is about. Destructive
verbs (reset, upgrade) classify as T3 in the executor, so they require a minted
approval and a single target.

Input hardening (BL-082, ADR-0016): post-verb tokens beginning with ``-`` are
refused, so a free-form action can no longer smuggle a talosctl option (for
example ``--talosconfig`` redirection, or ``--recover-skip-hash-check`` on an
etcd restore, BL-022); options the adapter needs are set from structured params.
Node and endpoint values must be an IP address or an RFC 1123 hostname. A reset
never wipes implicitly: ``--wipe-mode`` is always explicit and defaults to
``system-disk``; ``all`` must be requested via the structured ``wipe_mode`` param
(BL-025). The structured ``system_labels`` param is the additive partition-scoped
alternative (BL-098): it maps to ``--system-labels-to-wipe`` (for example
``EPHEMERAL``), which preserves the ``STATE`` partition so the node rejoins the
cluster instead of needing a full re-provision; it is mutually exclusive with
``wipe_mode`` (supplying both is refused). A real-run upgrade is gated on a
pre-flight ``talosctl health`` HARD precondition (BL-023).
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess  # noqa: S404 - pre-flight health probe; argv is adapter-built and gated
from collections.abc import Mapping
from dataclasses import replace
from typing import ClassVar

from praxis.actuation.base import ActuationAdapter, HostInfo, scrubbed_env
from praxis.execution.contract import Approval, Predicate, Severity
from praxis.execution.patterns import Tier
from praxis.execution.runner import ExecutionRequest
from praxis.model.facts import HostType

# An allowlist of talosctl subcommands, so a free-form ``action`` string can no
# longer smuggle an arbitrary or typo'd verb into the argv (BL-048). New verbs are
# added here deliberately; an unknown verb is refused before the argv is built.
_TALOSCTL_VERBS: frozenset[str] = frozenset(
    {
        # read-only / diagnostic
        "version",
        "health",
        "get",
        "list",
        "read",
        "dmesg",
        "logs",
        "services",
        "containers",
        "memory",
        "processes",
        "stats",
        "disks",
        "mounts",
        "time",
        "members",
        "kubeconfig",
        # stateful
        "apply-config",
        "patch",
        "bootstrap",
        # destructive (classify T3 in the executor)
        "reset",
        "upgrade",
        "upgrade-k8s",
        "reboot",
        "shutdown",
        "etcd",
    }
)

# Wipe scopes for ``talosctl reset`` (BL-025). The adapter always passes an
# explicit ``--wipe-mode``; the default keeps user data disks.
_WIPE_MODES: frozenset[str] = frozenset({"system-disk", "user-disks", "all"})
_DEFAULT_WIPE_MODE = "system-disk"

# Partition labels for the additive ``--system-labels-to-wipe`` reset scope (BL-098).
# This is the partition-granular alternative to the disk-granular ``--wipe-mode``:
# wiping only ``EPHEMERAL`` preserves the ``STATE`` partition (node identity and
# secrets), so the node reboots back into the cluster rather than needing a full
# re-provision. The two scopes are mutually exclusive; supplying both is refused
# (fail closed on ambiguity). The label set is an allowlist, normalised to the
# uppercase Talos spelling.
_SYSTEM_LABELS: frozenset[str] = frozenset({"EPHEMERAL", "STATE"})

# Verbs whose real run requires a passing pre-flight health check (BL-023).
_HEALTH_GATED_VERBS: frozenset[str] = frozenset({"upgrade", "upgrade-k8s"})

_RFC1123_HOST = re.compile(
    r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)


def _validate_node(value: str) -> None:
    """A node/endpoint must be an IP address or an RFC 1123 hostname (BL-082).

    Anything else (an option-shaped string, whitespace, an empty value) is
    refused before the argv is built, closing the ``--talosconfig``-style
    flag-injection residual of BL-047/BL-048.
    """
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if not _RFC1123_HOST.match(value):
        raise ValueError(f"talos node/endpoint is not an IP or RFC 1123 hostname: {value!r}")


def _validate_system_labels(value: str) -> str:
    """Validate a comma-separated partition-label list against the allowlist (BL-098).

    Returns the normalised (uppercase, comma-joined) value, or raises if any token
    is empty or outside ``_SYSTEM_LABELS``. The result reaches ``talosctl`` as the
    value of ``--system-labels-to-wipe`` after the structured-param checks, so a
    free-form ``action`` string can never inject a partition label.
    """
    tokens = [tok.strip().upper() for tok in value.split(",")]
    if not all(tokens) or any(tok not in _SYSTEM_LABELS for tok in tokens):
        raise ValueError(
            f"talosctl reset system_labels must be a comma list of {sorted(_SYSTEM_LABELS)}, "
            f"got {value!r} (BL-098)"
        )
    return ",".join(tokens)


class TalosctlAdapter(ActuationAdapter):
    name: ClassVar[str] = "talosctl"
    supported: ClassVar[frozenset[HostType]] = frozenset({HostType.TALOS})
    base_tier: ClassVar[Tier] = Tier.T2
    native_dry_run: ClassVar[bool] = False

    def build_request(
        self,
        host: HostInfo,
        action: str,
        params: Mapping[str, object] | None = None,
        *,
        dry_run: bool = True,
        approval: Approval | None = None,
    ) -> ExecutionRequest:
        request = super().build_request(host, action, params, dry_run=dry_run, approval=approval)
        if host.nodes:
            # The T3 single-target gate keys off ``request.target``; for talosctl the
            # real targets are the nodes, not host.name. Reflect them so a multi-node
            # destructive call (reset/upgrade across the control plane at once) is
            # refused by the executor's one-target-at-a-time rule, not just a
            # multi-name one (BL-047). A comma in the target trips _is_multi_target.
            return replace(request, target=",".join(host.nodes))
        return request

    def build_argv(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[str]:
        parts = action.split()
        if not parts:
            raise ValueError("talosctl requires a verb")
        verb = parts[0]
        if verb not in _TALOSCTL_VERBS:
            raise ValueError(
                f"talosctl verb not allowed: {verb!r} (allowed: {sorted(_TALOSCTL_VERBS)})"
            )
        for token in parts[1:]:
            if token.startswith("-"):
                raise ValueError(
                    f"talosctl option not accepted in action: {token!r}; options are "
                    "set by the adapter from structured params (BL-082)"
                )
        for value in (*host.nodes, *host.endpoints):
            _validate_node(value)
        argv = ["talosctl"]
        if host.nodes:
            argv += ["--nodes", ",".join(host.nodes)]
        if host.endpoints:
            argv += ["--endpoints", ",".join(host.endpoints)]
        argv += parts
        if verb == "reset":
            system_labels = params.get("system_labels")
            if system_labels:
                # Partition-scoped reset (BL-098): preserves STATE so the node can
                # rejoin. Mutually exclusive with the disk-scoped --wipe-mode.
                if params.get("wipe_mode"):
                    raise ValueError(
                        "talosctl reset takes either wipe_mode or system_labels, not both "
                        "(BL-098: fail closed on an ambiguous reset scope)"
                    )
                if not isinstance(system_labels, str):
                    raise ValueError(
                        f"talosctl reset system_labels must be a string, got {system_labels!r}"
                    )
                argv += ["--system-labels-to-wipe", _validate_system_labels(system_labels)]
            else:
                wipe_mode = params.get("wipe_mode") or _DEFAULT_WIPE_MODE
                if not isinstance(wipe_mode, str) or wipe_mode not in _WIPE_MODES:
                    raise ValueError(
                        f"talosctl reset wipe_mode must be one of {sorted(_WIPE_MODES)}, "
                        f"got {wipe_mode!r} (BL-025)"
                    )
                argv += ["--wipe-mode", wipe_mode]
        return argv

    def extra_preconditions(
        self, host: HostInfo, action: str, params: Mapping[str, object], *, dry_run: bool
    ) -> list[Predicate[ExecutionRequest]]:
        """A real-run upgrade requires a passing pre-flight health check (BL-023)."""
        verb = action.split()[0] if action.split() else ""
        if dry_run or verb not in _HEALTH_GATED_VERBS:
            return []
        return [
            Predicate[ExecutionRequest](
                name="talos_health",
                test=lambda _req: self._health_ok(host),
                severity=Severity.HARD,
                message=(
                    f"talosctl health pre-flight failed for {host.name}; refusing {verb} (BL-023)"
                ),
            )
        ]

    @staticmethod
    def _health_ok(host: HostInfo) -> bool:
        """Run ``talosctl health`` against the host; any failure refuses (fail closed).

        Nodes and endpoints are re-validated here, not only in ``build_argv``, so
        the probe stays injection-safe even if a future code path reaches the
        precondition without building the main argv first (BL-082).
        """
        for value in (*host.nodes, *host.endpoints):
            _validate_node(value)  # a throwing predicate is a HARD audited refusal
        argv = ["talosctl"]
        if host.nodes:
            argv += ["--nodes", ",".join(host.nodes)]
        if host.endpoints:
            argv += ["--endpoints", ",".join(host.endpoints)]
        argv += ["health"]
        if shutil.which(argv[0]) is None:
            return False
        try:
            proc = subprocess.run(  # noqa: S603 - adapter-built argv, no shell
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=60,
                env=scrubbed_env(),
                start_new_session=True,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return proc.returncode == 0
