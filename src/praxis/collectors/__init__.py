"""Read-only host telemetry normalized into bitemporal fact envelopes (BL-007).

Each collector is a pure parser (`Collector.parse`). The executor runs the T0 read
that produces the raw output; collectors only normalize it to facts, treating all
collected output as untrusted data (SEC-4). osquery and AIDE are the first-class
collectors; a generic command probe and a talos collector cover the rest, with
Windows/cloud depth staged (see LIMITATIONS).
"""

from __future__ import annotations

from praxis.collectors.aide import AideCollector
from praxis.collectors.base import Collector
from praxis.collectors.cis import CisCollector
from praxis.collectors.osquery import OsqueryCollector
from praxis.collectors.probe import CommandProbeCollector
from praxis.collectors.talos import TalosCollector

__all__ = [
    "AideCollector",
    "CisCollector",
    "Collector",
    "CommandProbeCollector",
    "OsqueryCollector",
    "TalosCollector",
]
