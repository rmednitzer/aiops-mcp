"""Smoke test: the package imports, exposes a version, and registers the expected tools."""

from __future__ import annotations

import praxis
from praxis.server import build_registry
from praxis.tools import REGISTERED_TOOLS


def test_package_version() -> None:
    assert isinstance(praxis.__version__, str)
    assert praxis.__version__


def test_register_all_registers_expected_tools() -> None:
    registry = build_registry()
    assert set(registry.names()) == set(REGISTERED_TOOLS)
