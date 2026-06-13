"""Compliance catalog model + bidirectional validator (BL-031, ADR-0021).

The integration test pins that the real catalog is consistent with the live code,
the STPA constraints, and the prose map (so a drift breaks CI). The unit tests build
a minimal synthetic repo and perturb one thing each, so every cross-reference rule
has a proving case.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from praxis.governance.catalog import ComplianceCatalog, load_catalog
from praxis.governance.validate import run, validate_catalog

ROOT = Path(__file__).resolve().parents[2]
REAL_CATALOG = ROOT / "docs" / "governance" / "compliance-controls.json"


# --------------------------------------------------------------- integration
def test_real_catalog_is_consistent() -> None:
    # The shipped catalog must pass every rule against the real tree: this is the
    # CI gate's assertion, re-run inside the suite so `make check` catches drift too.
    assert run(ROOT, REAL_CATALOG) == []


def test_real_catalog_covers_all_sec_constraints() -> None:
    catalog = load_catalog(REAL_CATALOG)
    sec = {cid for cid in catalog.controls if cid.startswith("SEC-")}
    assert sec == {f"SEC-{n}" for n in range(1, 11)}


# ------------------------------------------------------------- synthetic repo
def _make_repo(tmp_path: Path) -> Path:
    """A minimal repo the validator can check: two SEC constraints, wired end to end."""
    (tmp_path / "docs" / "stpa").mkdir(parents=True)
    (tmp_path / "docs" / "stpa" / "07-security-constraints.md").write_text(
        "| ID | Constraint |\n|----|-----------|\n"
        "| SEC-1 | deny is global |\n| SEC-2 | one audited path |\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "governance").mkdir(parents=True)
    (tmp_path / "docs" / "governance" / "compliance-map.md").write_text(
        "Maps SEC-1 and SEC-2 to frameworks.\n", encoding="utf-8"
    )
    src = tmp_path / "src" / "praxis" / "execution"
    src.mkdir(parents=True)
    (src / "policy.py").write_text('"""deny-first (SEC-1)."""\n', encoding="utf-8")
    (src / "runner.py").write_text('"""one path (SEC-2)."""\n', encoding="utf-8")
    tests = tmp_path / "tests" / "execution"
    tests.mkdir(parents=True)
    (tests / "test_policy.py").write_text("def test_deny() -> None:\n    pass\n", encoding="utf-8")
    (tests / "test_runner.py").write_text("def test_path() -> None:\n    pass\n", encoding="utf-8")
    return tmp_path


def _catalog_dict() -> dict[str, Any]:
    return {
        "version": "1",
        "frameworks": {"EU AI Act": "Regulation (EU) 2024/1689"},
        "controls": {
            "SEC-1": {
                "title": "deny",
                "statement": "global deny",
                "invariants": [2],
                "modules": ["src/praxis/execution/policy.py"],
                "proving_tests": ["tests/execution/test_policy.py::test_deny"],
                "regulatory": [{"framework": "EU AI Act", "article": "Art. 9"}],
                "status": "implemented",
            },
            "SEC-2": {
                "title": "path",
                "statement": "one path",
                "invariants": [1],
                "modules": ["src/praxis/execution/runner.py"],
                "proving_tests": ["tests/execution/test_runner.py::test_path"],
                "regulatory": [{"framework": "EU AI Act", "article": "Art. 12"}],
                "status": "implemented",
            },
        },
    }


def _validate(repo: Path, data: dict[str, Any]) -> list[str]:
    return validate_catalog(repo, ComplianceCatalog.model_validate(data))


def test_minimal_repo_and_catalog_pass(tmp_path: Path) -> None:
    assert _validate(_make_repo(tmp_path), _catalog_dict()) == []


def test_bad_id_format_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC1"] = data["controls"].pop("SEC-2")
    out = _validate(_make_repo(tmp_path), data)
    assert any("R2 id-format" in e for e in out)


def test_sec_must_match_stpa(tmp_path: Path) -> None:
    data = _catalog_dict()
    del data["controls"]["SEC-2"]  # STPA defines SEC-2 but the catalog omits it
    out = _validate(_make_repo(tmp_path), data)
    assert any("R3 stpa" in e and "SEC-2" in e for e in out)


def test_missing_module_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["modules"] = ["src/praxis/execution/nope.py"]
    out = _validate(_make_repo(tmp_path), data)
    assert any("R4 module" in e for e in out)


def test_missing_back_citation_is_flagged(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    # runner.py carries SEC-2, not SEC-1: citing it under SEC-1 is a broken link.
    data = _catalog_dict()
    data["controls"]["SEC-1"]["modules"] = ["src/praxis/execution/runner.py"]
    out = _validate(repo, data)
    assert any("R5 back-citation" in e for e in out)


def test_dangling_sec_token_in_source_is_flagged(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    (repo / "src" / "praxis" / "execution" / "runner.py").write_text(
        '"""references SEC-2 and a stray SEC-9 (SEC-9 has no control)."""\n', encoding="utf-8"
    )
    out = _validate(repo, _catalog_dict())
    assert any("R6 dangling" in e and "SEC-9" in e for e in out)


def test_invariant_out_of_range_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["invariants"] = [12]
    out = _validate(_make_repo(tmp_path), data)
    assert any("R7 invariant" in e for e in out)


def test_unknown_framework_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["regulatory"] = [{"framework": "MADE-UP", "article": "X"}]
    out = _validate(_make_repo(tmp_path), data)
    assert any("R8 framework" in e and "MADE-UP" in e for e in out)


def test_uncovered_framework_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["frameworks"]["GDPR"] = "Regulation (EU) 2016/679"  # in scope but never cited
    out = _validate(_make_repo(tmp_path), data)
    assert any("R8 coverage" in e and "GDPR" in e for e in out)


def test_missing_proving_test_is_flagged(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["proving_tests"] = ["tests/execution/test_policy.py::test_absent"]
    out = _validate(_make_repo(tmp_path), data)
    assert any("R9 test" in e for e in out)


def test_proving_test_must_be_path_function_form(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["proving_tests"] = ["tests/execution/test_policy.py"]
    out = _validate(_make_repo(tmp_path), data)
    assert any("R9 test" in e and "path::function" in e for e in out)


def test_implemented_control_needs_a_proving_test(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["proving_tests"] = []  # implemented but untested
    out = _validate(_make_repo(tmp_path), data)
    assert any("R9 test" in e and "names no proving test" in e for e in out)


def test_partial_control_is_exempt_from_proving_test_rule(tmp_path: Path) -> None:
    data = _catalog_dict()
    data["controls"]["SEC-1"]["proving_tests"] = []
    data["controls"]["SEC-1"]["status"] = "partial"
    data["controls"]["SEC-1"]["tracking"] = "BL-001"
    out = _validate(_make_repo(tmp_path), data)
    assert not any("names no proving test" in e for e in out)


def test_map_parity_is_flagged(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    # The prose map cites SEC-3, which the catalog does not define.
    (repo / "docs" / "governance" / "compliance-map.md").write_text(
        "Maps SEC-1, SEC-2, and SEC-3.\n", encoding="utf-8"
    )
    out = _validate(repo, _catalog_dict())
    assert any("R10 map-parity" in e and "SEC-3" in e for e in out)


def test_status_tracking_coherence(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    partial = _catalog_dict()
    partial["controls"]["SEC-1"]["status"] = "partial"  # partial with no tracking
    assert any("R11 tracking" in e for e in _validate(repo, partial))
    extra = _catalog_dict()
    extra["controls"]["SEC-1"]["tracking"] = "BL-999"  # implemented but tracked
    assert any("R11 tracking" in e for e in _validate(repo, extra))


def test_malformed_catalog_is_reported_not_raised(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path)
    bad = repo / "bad.json"
    bad.write_text(json.dumps({"version": "1"}), encoding="utf-8")  # missing required keys
    out = run(repo, bad)
    assert out and any("R1 schema" in e for e in out)


def test_unreadable_catalog_is_reported(tmp_path: Path) -> None:
    out = run(_make_repo(tmp_path), tmp_path / "does-not-exist.json")
    assert out and any("R1 schema" in e for e in out)
