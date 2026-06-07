"""Smoke test: the package imports and exposes a version. Real tests arrive with each BL item."""

from __future__ import annotations

import praxis


def test_package_version() -> None:
    assert isinstance(praxis.__version__, str)
    assert praxis.__version__
