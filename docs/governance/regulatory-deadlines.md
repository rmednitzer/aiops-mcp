# Regulatory deadlines

A working reference of the application and transition dates for the frameworks the
project maps in `docs/governance/compliance-map.md` (BL-036). This is not legal
advice; verify each date against the Official Journal of the European Union (and the
Austrian Federal Law Gazette) before relying on it. Dates are ISO 8601.

The point of tracking these here is operational: a control that is "planned" in the
compliance map (annotated with a `BL-NNN`) should close before the obligation it
serves applies. The "Relevant project controls" column names where to look.

## EU frameworks

| Framework | Milestone | Date | Relevant project controls |
|-----------|-----------|------|---------------------------|
| EU AI Act, Regulation (EU) 2024/1689 | Entry into force | 2024-08-01 | compliance-map "EU AI Act" rows |
| EU AI Act | Prohibited practices (Chapter II) apply | 2025-02-02 | n/a (praxis defines no prohibited-practice system) |
| EU AI Act | GPAI model obligations apply | 2025-08-02 | n/a (praxis ships no GPAI model) |
| EU AI Act | High-risk obligations (Annex III stand-alone) apply | 2027-12-02 (deferred; statutory date was 2026-08-02) | Art. 12 logging (`execution/audit.py`), Art. 14 oversight (`execution/runner.py`) |
| EU AI Act | High-risk obligations (Annex I products) apply | 2028-08-02 (deferred; statutory date was 2027-08-02) | as above |
| NIS2, Directive (EU) 2022/2555 | Member-State transposition deadline | 2024-10-17 | compliance-map "NIS2" rows |
| NIS2 | Measures apply in transposing States | 2024-10-18 | SEC-8 least privilege/kill switch; SEC-2/SEC-9 audit evidence |
| NISG 2026 (Austria) | National NIS2 transposition (in progress) | 2026 | as NIS2; expected 2026, tracked because Austria missed the 2024-10-17 deadline |
| Cyber Resilience Act, Regulation (EU) 2024/2847 | Entry into force | 2024-12-10 | compliance-map "Cyber Resilience Act" rows |
| CRA | Reporting obligations (Art. 14) apply | 2026-09-11 | SEC-2/SEC-9 audit evidence; vulnerability handling CI |
| CRA | Main obligations apply | 2027-12-11 | secure-by-default posture; digest-pin/SBOM (BL-033, BL-092) |
| GDPR, Regulation (EU) 2016/679 | Applicable | 2018-05-25 | SEC-9 redaction; SEC-4 classification filtering |
| ISO/IEC 27001 | 2013-to-2022 certification transition deadline | 2025-10-31 | compliance-map "ISO/IEC 27001:2022" rows |

## Notes

- praxis is a tool an operator runs, not itself a regulated AI system, a NIS2 essential
  entity, or a CRA manufacturer of record. These dates are the obligations of the
  operator and their organisation; the project's job is to make the supporting evidence
  and controls available before the relevant date (see the compliance map).
- The CRA dates follow the staggered schedule in the Regulation: reporting obligations
  21 months after entry into force, the remaining obligations 36 months after.
- The AI Act high-risk dates are the two staggered application dates (Annex III systems,
  then Annex I regulated products); the earlier prohibited-practice and GPAI dates are
  listed for completeness even though praxis triggers neither.
- The high-risk dates above carry the deferral agreed in the Digital Omnibus on AI, a
  targeted amendment package to Regulation (EU) 2024/1689. The co-legislators reached a
  provisional agreement on 2026-05-07: Annex III stand-alone high-risk obligations move
  from 2026-08-02 to 2027-12-02 (16 months), and Annex I product-embedded high-risk
  obligations move from 2027-08-02 to 2028-08-02 (12 months). As of this writing
  (2026-06) the package is politically agreed but not yet formally adopted or published
  in the Official Journal; formal adoption is expected before the 2026-08-02 statutory
  date it supersedes. Treat the deferred dates as provisional and re-confirm both the
  dates and the in-force status against the Official Journal once it publishes
  (tracked as BL-113; the original statutory dates remain in force until then). The same
  package adds two prohibited practices under Art. 5 (AI-generated non-consensual
  intimate imagery and CSAM); praxis defines no such system, so its prohibited-practice
  disposition is unchanged.
