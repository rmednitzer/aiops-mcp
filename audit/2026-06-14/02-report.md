# Deep audit 2026-06-14: final report

Date: 2026-06-14
Decision record: ADR-0040. Baseline and method: `00-baseline.md`. Findings: `01-findings.md`.

## Result

No critical or high findings. The praxis security spine holds: each of the nine
invariants is mechanically enforced with a passing test (re-confirmed in code this pass),
STPA traceability is complete (28/28 UCAs covered, 10/10 SEC constraints enforced, the
compliance validator reports 0 violations across 11 rules), and the adversarial probe
matrix and the 20000-iteration fuzz run found no bypass of redaction, the SSRF egress
filter, tier round-up, the transport guard, or the append-only store.

The pass produced six code findings, all Medium or Low, all remediated in this pass with
regression tests, plus three documented dispositions and a documentation-drift sweep.

## Disposition

| ID | Sev | Disposition | Where |
|----|-----|-------------|-------|
| F-001 audit `_canonical` never-raises | Medium | Fixed + test | `execution/audit.py` |
| F-006 Anthropic/HF/DigitalOcean redaction | Medium | Fixed + test | `execution/redaction.py` |
| F-007 supersede rowcount race (both backends) | Medium | Fixed + test | `store/{sqlite,postgres}.py` |
| F-004 `rm -rf //` / `/*` deny miss | Low | Fixed + test (PATTERNS_VERSION 3->4) | `execution/patterns.py` |
| F-008 Talos non-JSON unbounded store | Low | Fixed + test | `collectors/talos.py` |
| F-003 OpenTofu unconfined `chdir` | Low | Fixed + test (re-add: BL-105) | `actuation/opentofu.py` |
| F-002 pattern-based redaction limit | Low/Info | Documented | `SECURITY.md` |
| F-005 syslog not SSRF-filtered | Disposed | Documented (operator-trusted) | `audit.py` docstring, `operate.md`, ADR-0037 note |
| F-009 ADR-0015 ratification note | Low | Added | `docs/adr/0015-*.md` |

Deferred hardening: BL-105 (OpenTofu `chdir` confinement), BL-106 (timing-safe approval
comparison), BL-107 (multi-client message-byte cap), BL-108 (probe collector caps),
BL-109 (exhaustive compliance proving-tests). BL-106 and BL-107 are HTTP-transport
(BL-012) prerequisites.

## Documentation brought current

`docs/architecture.md` (runtime checkpoints and the RFC 3161 TSA are delivered, not "v0
gap"); `README.md` (ADR range; `PRAXIS_TSA_CERT`; the ADR-0038 correlation fields);
`SECURITY.md` (`PRAXIS_TSA_CERT`; the pattern-based redaction note); `LIMITATIONS.md`
(ADR range; SSRF/anchoring/CI gating now delivered; HTTP transport the remaining open
item); `docs/runbooks/self-audit.md` ("until BL-095 lands" removed); `docs/runbooks/operate.md`
(new "Audit sinks and stamping" section); `docs/governance/compliance-map.md` (three
stale "v0 gap" annotations removed for resolved BL-051/076/033/088; `inv 5`->`inv 4`
typo). ADR README index and prose extended for ADR-0040.

## Gate evidence (this pass)

- `make ci-success`: green, 92% coverage (above floor), after the remediations.
- `mypy` strict: clean, 64 source files. `ruff`: clean (`src tests scripts`).
- `scripts/fuzz.py 20000`: no violations (classify/policy/redaction/manifest/merkle/evidence).
- Adversarial probe matrix (`00-baseline.md`): all controls held except the F-001/F-006
  deviations, now fixed and re-probed green.
- `pip-audit` unavailable this session; runtime surface is one bounded dependency
  (`pydantic>=2,<3`) and CI runs dependency-review plus a hash-locked dev lock.

## Sign-off

The remediations and documentation updates ship in one change with ADR-0040 and these
artifacts. The posture is unchanged where it was already strong and strictly improved
where the six findings were closed. Next periodic pass: re-run this method; the open BL
items (especially BL-106/107) gate the HTTP transport.
