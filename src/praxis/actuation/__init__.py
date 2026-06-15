"""Actuation adapters (BL-009): wrap a real tool, gate on host_type, route through
the executor (ADR-0005). DRY_RUN -> approve -> execute; T3 needs a typed token and
a single target (SEC-5, SEC-6). Redfish OOB, cloud-API depth, and kubectl/helm
(the last gated on the ADR-0043 scoped-kubeconfig contract, BL-111) are staged (see
LIMITATIONS); ssh/ansible/opentofu/talosctl/runbook cover the current fleet.
"""

from __future__ import annotations

from praxis.actuation.ansible import AnsibleAdapter
from praxis.actuation.base import ActuationAdapter, HostInfo, run_subprocess
from praxis.actuation.credentials import CredentialBroker, CredentialError, Scope
from praxis.actuation.opentofu import OpenTofuAdapter
from praxis.actuation.runbook import RunbookAdapter
from praxis.actuation.ssh import SSHAdapter
from praxis.actuation.talosctl import TalosctlAdapter

__all__ = [
    "ActuationAdapter",
    "AnsibleAdapter",
    "CredentialBroker",
    "CredentialError",
    "HostInfo",
    "OpenTofuAdapter",
    "RunbookAdapter",
    "SSHAdapter",
    "Scope",
    "TalosctlAdapter",
    "run_subprocess",
]
