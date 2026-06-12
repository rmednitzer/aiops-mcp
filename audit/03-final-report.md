# Audit phase 8: final report

Date: 2026-06-12
Repository: `rmednitzer/aiops-mcp` (product `praxis`)
Audited HEAD at start: `dc69596`
Branch: `claude/youthful-turing-3b12uf` (session-designated; the prompt named
`audit/2026-06-12-full-pass`, recorded as a deliberate environment-mandated
deviation in `audit/00-inventory.md`)

## Executive summary

`praxis` is a security-first MCP server that had already been through four audit
and remediation waves (ADR-0011 through ADR-0016) before this pass. This was a
full, phased, read-only audit followed by governance write-back. The result is a
clean bill of health on the spine: no Critical, High, or Medium findings, all five
CI gates green, no known dependency vulnerabilities, and no secrets in the tree or
in history. The audit's net contribution is fresh, command-backed evidence; one
sharpened governance-traceability finding (a resolved backlog item fixed on only
one of two store backends); and three new backlog items.

No code was changed. The single finding with a concrete code fix is a Postgres
schema change that the ground rules route to the backlog and that cannot be
regression-tested in this environment. Shipping it untested would violate the
project's own "no behavior change without a test" rule, so it is filed, not forced.

## Baseline vs post-fix metrics

No fixes were applied, so the baseline is also the exit state. It is recorded here
as the regression reference.

| Metric | Baseline (2026-06-12) | Exit |
|---|---|---|
| Tests | 226 passed, 1 skipped (optional psycopg), 0 failed | unchanged |
| Test runtime | about 2.6 s, no flakiness over 3 runs | unchanged |
| Lint (ruff) | 0 violations | unchanged |
| Format (ruff) | 0 diffs, 111 files | unchanged |
| Types (mypy strict) | 0 errors, 107 files | unchanged |
| Schema drift | none | unchanged |
| Eval gate | P@1 1.000, MRR 1.000, n=8, PASS | unchanged |
| Coverage (ad hoc) | 94 percent statements | unchanged |
| Dependency vulns | 0 (pip-audit 2.10.1) | unchanged |
| Secrets (tree + history) | 0 real (only doc-example AWS key, fake PEM) | unchanged |
| Fuzz | 200000 iterations, 0 violations | unchanged |

Vulnerability counts by severity (this pass): Critical 0, High 0, Medium 0,
Low 1 (Q-01), Info 4 (Q-02..Q-05). Two of the Info items were already tracked
(BL-088); three became BL-091..BL-093.

## Commits in this audit branch

Each is one concern; evidence and remediation are not mixed.

1. `chore(audit): phase 0 recon and inventory report` - component map, dependency
   graph, toolchain versions (`audit/00-inventory.md`).
2. `chore(audit): phase 1 validation baseline (226 passed, all gates green)` - the
   regression baseline and CI-drift notes (`audit/01-baseline.md`).
3. `chore(audit): phase 2-3 findings register (no critical/high/medium; 1
   sharpened, 4 info)` - the findings register with the OWASP-relevant pass and
   per-finding evidence (`audit/02-security-findings.md`).
4. `docs(audit): phase 6-7 governance write-back (ADR-0017, BL-091..BL-093)` -
   ADR-0017 (Accepted), the ADR index entry, the three backlog items, and the
   CHANGELOG entry.
5. `docs(audit): phase 8 final report` - this file.

## Residual risk statement

- BL-091 (Low): the Postgres backend's `MAX(seq)+1` race is unmitigated; on a
  single-process, single-operator deployment (the default) it is latent, and it
  becomes reachable only with concurrent writers against one database (Helm
  `replicaCount` > 1, or a future HTTP transport with multiple workers). Impact is
  silent fact-ordering corruption, not a confidentiality or actuation bypass.
- Runtime audit anchoring is still not produced (BL-076): the trail is a keyless
  hash chain, and the default `LocalStamper` is forgeable by anyone who can write
  the evidence file. v0 tamper-evidence rests on the hash chain plus
  operating-system append-only storage when an audit file is configured. This is a
  known, documented limitation, not a regression.
- HTTP transport is unimplemented and fails closed; the Helm/zarf artifacts encode
  a forward posture and are not runnable as shipped (BL-093, BL-012). No exposure.
- Supply chain: the dependency surface is minimal and vuln-free today, but dev
  tools float without a lockfile (BL-088) and no reviewable Dockerfile backs the
  referenced image (BL-092). Reproducibility and reviewability gaps, not live
  vulnerabilities.

Overall: the design's load-bearing controls (single audited path, tiered authority
with a deny-first gate, human-binding minted approvals, storage-layer append-only,
fail-closed SSRF and transport guards, in-path trifecta containment, broad
pre-audit redaction) are present in code, tested, and verified this pass. The
residual risk is concentrated in deferred structural items that are openly tracked.

## Top 5 backlog items (by severity then leverage)

1. BL-076 (L, open) - wire runtime audit anchoring and a non-forgeable stamper;
   until then make operating-system append-only a required, documented deploy
   control. The largest gap between the designed and the running tamper-evidence.
2. BL-091 (S, open, new) - close the Postgres `seq` race with a unique index, to
   parity with SQLite; the one concrete code finding from this pass.
3. BL-088 (S, open) - pin dev tools and the fuzz/sbom interpreter and add a
   hash-locked dev requirements file, so the CI gate is reproducible over time.
4. BL-087 (M, open) - finish the deploy hardening (systemd `PrivateUsers`/
   `ProcSubset`/`RemoveIPC`/`IPAddressDeny`, scoped NetworkPolicy egress, sandbox
   `runtimeClassName`).
5. BL-046 (M, open) - make the SSRF filter hostname-resolving and rebinding-aware,
   and wire it into the egress path, so a named host is checked rather than
   refused outright.

## Method note and deviations

- Tooling actually available is recorded in `audit/00-inventory.md`. semgrep,
  gitleaks, and trufflehog were absent; the SAST and secret phases used a manual
  OWASP-relevant code pass and a regex sweep of the tree and full history, both
  documented with evidence.
- Governance deliverables were adapted to this repo's stricter, established scheme
  (`docs/adr/NNNN-*.md` and `docs/backlog.md` with stable `BL-NNN` ids) rather
  than the generic root `BACKLOG.md` and parallel MADR folder the prompt described;
  the rationale is in ADR-0017 Decision 4. The `audit/` evidence reports are
  net-new and conflict with nothing.
- No stop condition was triggered: the suite runs, no secret rotation appears
  exploited, no fix required a major bump or data migration (the one schema change
  is deferred), and no repo content conflicted with the audit in a way that forced
  a halt.
