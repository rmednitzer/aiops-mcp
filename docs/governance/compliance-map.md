# Compliance map

Maps the project's controls (the nine invariants and the STPA security constraints
SEC-1..SEC-10) to regulatory frameworks, and onward to the enforcing code. Citations
use the original-language convention (Art. for EU law). This is a working mapping,
not legal advice. The authoritative control derivation is
`docs/stpa/07-security-constraints.md`.

## EU AI Act (Regulation (EU) 2024/1689)

| Reference | Project control | SEC / invariant | Enforcement |
|-----------|-----------------|-----------------|-------------|
| Art. 9 (risk management) | Conservative pre-execution tier classification | SEC-3 / inv 2 | `execution/patterns.py`, `execution/policy.py::classify` |
| Art. 12 (logging and traceability) | Tamper-evident, append-only audit trail | SEC-2, SEC-9 / inv 1, 3 | `execution/audit.py`, `audit/evidence.py` |
| Art. 14 (human oversight) | Tiered HITL at T2+, typed token at T3 | SEC-2, SEC-6 / inv 6 | `execution/runner.py`, `drift/converge.py` |
| Art. 15 (accuracy, robustness, cybersecurity) | Bitemporal source of truth; drift detection; SSRF filter | SEC-7, SEC-10 / inv 4, 7 | `store/sqlite.py`, `drift/`, `_ssrf.py` |

## NIS2 (Directive (EU) 2022/2555) and NISG 2026 (Austria)

| Reference | Project control | SEC / invariant | Enforcement |
|-----------|-----------------|-----------------|-------------|
| Art. 21 (risk-management measures) | Least privilege; scoped, revocable credentials; kill switch | SEC-8 / inv 9 | `actuation/credentials.py`, `execution/runner.py::KillSwitch` |
| Art. 21 (asset and configuration management) | Drift detection against desired state | SEC-6 / inv 6 | `drift/engine.py`, `drift/sources.py` |
| Art. 23 (reporting) | Complete, verifiable audit evidence for incident reconstruction | SEC-2, SEC-9 / inv 3 | `audit/verify_evidence`, `scripts/verify_audit.py` |

## Cyber Resilience Act (Regulation (EU) 2024/2847)

| Reference | Project control | SEC / invariant | Enforcement |
|-----------|-----------------|-----------------|-------------|
| Annex I 1 (secure by design / default) | Default-deny posture; stdio default; fail-closed HTTP | SEC-7 / inv 7 | `config.py::validate_transport`, the Helm default-deny NetworkPolicy |
| Annex I 1 (no known exploitable vulns; supply chain) | Digest-pinned image; SBOM; dependency review; SHA-pinned CI | inv (supply chain) | `deploy/`, `.github/workflows/{sbom,dependency-review}.yml` |
| Annex I 2 (vulnerability handling) | CodeQL, nightly fuzz, the STPA revisit triggers | SEC-1..SEC-10 | `.github/workflows/{codeql,fuzz}.yml` |

## GDPR (Regulation (EU) 2016/679) and Austrian DSG

| Reference | Project control | SEC / invariant | Enforcement |
|-----------|-----------------|-----------------|-------------|
| Art. 25 (data protection by design and default) | No output bodies stored; classification filtering | SEC-9, SEC-4 | `execution/audit.py`, `context.py::filter_restricted` |
| Art. 32 (security of processing) | Redaction of secrets; tamper-evident integrity | SEC-9 / inv 3 | `execution/redaction.py`, `audit/merkle.py` |

## ISO/IEC 27001:2022 (Annex A)

| Reference | Project control | SEC / invariant | Enforcement |
|-----------|-----------------|-----------------|-------------|
| A.5.15 (access control) | Tiered authority; per-role scoped credentials | SEC-3, SEC-8 / inv 2, 9 | `execution/policy.py`, `actuation/credentials.py` |
| A.8.15 (logging) | Append-only, hash-chained audit; redacted params | SEC-2, SEC-9 / inv 1, 3 | `execution/audit.py` |
| A.8.16 (monitoring activities) | Drift findings as bitemporal facts | SEC-6 / inv 5 | `drift/`, `store/` |
| A.8.28 (secure coding) | mypy strict, ruff (incl. bandit S-rules), CodeQL, fuzz | n/a | `pyproject.toml`, CI |

Every row traces through a SEC constraint to a proving test in
`docs/stpa/07-security-constraints.md`; a control without a test is a visible gap.
