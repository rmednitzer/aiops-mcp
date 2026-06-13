"""Bidirectional cross-reference rules over the compliance catalog (BL-031, ADR-0021).

``validate_catalog`` returns a list of human-readable violation strings; an empty
list means the catalog is consistent with the code, the STPA constraints, and the
prose compliance map. ``run`` loads the catalog and validates it, turning a
structural ``ValidationError`` into a violation string rather than a traceback.

The rules realise a compliance-as-code approach (a control catalog plus a validator
gated in CI, a proven fleet-operations pattern reimplemented natively here, no
cross-repo coupling per ADR-0001/0014), keyed on praxis's existing SEC-N / invariant
/ module / test traceability rather than a parallel control namespace:

- R1  the document parses through the pydantic model.
- R2  every control id is ``SEC-<n>`` or ``CTL-<nnn>``.
- R3  the SEC controls are exactly the STPA security constraints (no gap, no extra).
- R4  every cited module path exists in the repo.
- R5  each SEC control's ``src/praxis`` module carries the matching ``SEC-N`` token
      (forward back-citation: the cited enforcement file references the constraint).
- R6  every ``SEC-N`` token in ``src/praxis`` names a catalog control (no dangling ref).
- R7  every cited invariant is in 1..9.
- R8  every regulatory framework is known, and every in-scope framework is cited.
- R9  every listed proving test ``path::function`` exists, and an implemented
      control names at least one (partial/planned controls are exempt).
- R10 every SEC the prose map cites exists in the catalog (derived-index parity).
- R11 a partial/planned control carries a tracking BL id; an implemented one does not.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import ValidationError

from praxis.governance.catalog import ComplianceCatalog, load_catalog

_SEC_ID = re.compile(r"^SEC-\d+$")
_CTL_ID = re.compile(r"^CTL-\d{3}$")
_SEC_TOKEN = re.compile(r"\bSEC-\d+\b")
# A row of the STPA 07 table opens with the constraint id: ``| SEC-1 | ...``.
_STPA_SEC_ROW = re.compile(r"^\|\s*(SEC-\d+)\s*\|")

_STPA_PATH = ("docs", "stpa", "07-security-constraints.md")
_MAP_PATH = ("docs", "governance", "compliance-map.md")


def _stpa_sec_ids(repo_root: Path) -> set[str]:
    text = repo_root.joinpath(*_STPA_PATH).read_text(encoding="utf-8")
    return {m.group(1) for line in text.splitlines() if (m := _STPA_SEC_ROW.match(line))}


def _map_sec_ids(repo_root: Path) -> set[str]:
    return set(_SEC_TOKEN.findall(repo_root.joinpath(*_MAP_PATH).read_text(encoding="utf-8")))


def _src_sec_tokens(repo_root: Path) -> dict[str, set[str]]:
    """Repo-relative ``src/praxis/**.py`` path -> the set of SEC tokens in that file."""
    src = repo_root / "src" / "praxis"
    out: dict[str, set[str]] = {}
    for py in sorted(src.rglob("*.py")):
        rel = py.relative_to(repo_root).as_posix()
        out[rel] = set(_SEC_TOKEN.findall(py.read_text(encoding="utf-8")))
    return out


def _check_proving_test(repo_root: Path, cid: str, test: str) -> str | None:
    if "::" not in test:
        return f"R9 test: {cid} proving test {test!r} is not in path::function form"
    rel, func = test.split("::", 1)
    path = repo_root / rel
    if not path.is_file():
        return f"R9 test: {cid} proving test file {rel!r} does not exist"
    if not re.search(rf"\bdef {re.escape(func)}\b", path.read_text(encoding="utf-8")):
        return f"R9 test: {cid} proving test {func!r} not found in {rel}"
    return None


def validate_catalog(repo_root: Path, catalog: ComplianceCatalog) -> list[str]:
    """Return the list of cross-reference violations (empty means consistent)."""
    errors: list[str] = []
    stpa = _stpa_sec_ids(repo_root)
    src_tokens = _src_sec_tokens(repo_root)
    framework_ids = set(catalog.frameworks)
    sec_controls = {cid for cid in catalog.controls if _SEC_ID.match(cid)}

    # R2: id format.
    for cid in catalog.controls:
        if not (_SEC_ID.match(cid) or _CTL_ID.match(cid)):
            errors.append(f"R2 id-format: control id {cid!r} is not SEC-<n> or CTL-<nnn>")

    # R3: the SEC controls are exactly the STPA security constraints.
    for cid in sorted(sec_controls - stpa):
        errors.append(f"R3 stpa: control {cid} is not defined in {'/'.join(_STPA_PATH)}")
    for sec in sorted(stpa - set(catalog.controls)):
        errors.append(f"R3 stpa: STPA constraint {sec} has no catalog control (coverage gap)")

    cited_frameworks: set[str] = set()
    for cid, control in catalog.controls.items():
        # R7: invariants in range.
        for inv in control.invariants:
            if not 1 <= inv <= 9:
                errors.append(f"R7 invariant: {cid} cites invariant {inv} outside 1..9")
        # R4: module existence.
        for mod in control.modules:
            if not (repo_root / mod).exists():
                errors.append(f"R4 module: {cid} cites missing path {mod!r}")
            # R5: forward back-citation for SEC controls in the source tree.
            elif (
                cid in sec_controls
                and mod.startswith("src/praxis/")
                and mod.endswith(".py")
                and cid not in src_tokens.get(mod, set())
            ):
                errors.append(
                    f"R5 back-citation: {cid} cites {mod}, but that file carries no {cid} token"
                )
        # R8: regulatory refs name a known framework.
        for ref in control.regulatory:
            cited_frameworks.add(ref.framework)
            if ref.framework not in framework_ids:
                errors.append(f"R8 framework: {cid} maps to unknown framework {ref.framework!r}")
        # R9: proving tests exist, and an implemented control names at least one
        # (the compliance map's "a control without a test is a visible gap" made a
        # build break; partial/planned controls are exempt, their gap is tracked).
        for test in control.proving_tests:
            if (problem := _check_proving_test(repo_root, cid, test)) is not None:
                errors.append(problem)
        if control.status == "implemented" and not control.proving_tests:
            errors.append(f"R9 test: implemented control {cid} names no proving test")
        # R11: status/tracking coherence.
        if control.status in ("partial", "planned") and not control.tracking:
            errors.append(f"R11 tracking: {cid} is {control.status} but names no tracking BL id")
        if control.status == "implemented" and control.tracking:
            errors.append(
                f"R11 tracking: {cid} is implemented but carries tracking {control.tracking!r}"
            )

    # R8: every in-scope framework is cited by at least one control.
    for fid in sorted(framework_ids - cited_frameworks):
        errors.append(f"R8 coverage: framework {fid!r} is in scope but no control maps to it")

    # R6: every SEC token in the source tree names a catalog control.
    for mod, tokens in src_tokens.items():
        for tok in sorted(tokens - set(catalog.controls)):
            errors.append(f"R6 dangling: {mod} references {tok}, which is not a catalog control")

    # R10: derived-index parity with the prose compliance map.
    for sec in sorted(_map_sec_ids(repo_root) - set(catalog.controls)):
        errors.append(f"R10 map-parity: compliance-map.md cites {sec}, absent from the catalog")

    return errors


def run(repo_root: Path, catalog_path: Path) -> list[str]:
    """Load and validate the catalog, returning all violations (R1 included)."""
    try:
        catalog = load_catalog(catalog_path)
    except ValidationError as exc:
        return [f"R1 schema: catalog failed model validation: {exc}"]
    except OSError as exc:
        return [f"R1 schema: catalog could not be read: {exc}"]
    return validate_catalog(repo_root, catalog)
