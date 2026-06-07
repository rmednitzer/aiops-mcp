# Compliance map (skeleton)

Maps the project's controls (the nine invariants and the STPA security
constraints) to regulatory frameworks. To be completed in `BL-015`. Citations use
the original-language convention (Art. for EU law). This is a working mapping, not
legal advice.

| Framework | Reference | Project control |
|-----------|-----------|-----------------|
| EU AI Act | Art. 9 (risk management) | Pre-execution tier classification and risk assessment in the executor |
| EU AI Act | Art. 12 (logging and traceability) | Tamper-evident audit trail (SC-1; invariant 3) |
| EU AI Act | Art. 13 (transparency) | Per-action auditable decision chain |
| EU AI Act | Art. 14 (human oversight) | Tiered HITL at T2+ (SC-2; invariant 6) |
| NIS2 / NISG 2026 | risk management, incident handling | Drift detection, audit, least privilege (invariants 4, 8, 9) |
| CRA (EU 2024/2847) | Annex I (secure by design) | Default-deny posture, digest-pinned deploy, scoped credentials |
| GDPR | Art. 32 (security of processing) | Redaction, classification filtering, no output bodies in audit |
| ISO/IEC 27001:2022 | A.8.x technical controls | The invariant set and the STPA constraints |

Each row is firmed up against the derived constraints in
`docs/stpa/07-security-constraints.md` as those are written.
