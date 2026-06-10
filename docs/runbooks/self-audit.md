# Runbook: periodic self-audit

Run on a schedule (for example monthly) and after any change to the security-review
surface (`execution/patterns.py`). The goal is to confirm the invariants still hold
in code and that the evidence is intact.

## 1. Evidence integrity

```
python scripts/verify_audit.py /var/lib/praxis/audit.jsonl
```

Fail-closed: a broken hash chain, a Merkle mismatch, a broken checkpoint chain, or
an invalid timestamp token all report `ok=False`. Investigate any failure as a
potential L-3 (audit tamper) event before anything else.

v0 note: the running server does not produce Merkle checkpoints or RFC 3161 tokens
(BL-076), so unless checkpoints were generated out-of-band the verifier validates
the per-entry hash chain and the Merkle, checkpoint, and timestamp checks have
nothing to assert. Treat the hash chain plus operating-system append-only storage
(`chattr +a` or WORM) as the v0 integrity control.

## 2. Invariant gates

```
make ci-success          # lint + type-check + test + schema-drift + eval
python scripts/fuzz.py 200000
```

All nine invariants have proving tests (see
`docs/stpa/07-security-constraints.md`). A red gate is a regression in a
load-bearing property, not a flake.

## 3. STPA coverage

- Every state-changing MCP tool appears in the UCA table (`docs/stpa/05-ucas.md`).
  When a tool is added, confirm its row exists.
- Every security constraint (`07-security-constraints.md`) still names a real
  enforcement mechanism and a passing test. A constraint whose test was deleted is
  a gap.

## 4. Pattern review

- Diff `execution/patterns.py` since the last audit. Any change MUST have bumped
  `PATTERNS_VERSION`; confirm the bump and that audit records since the change
  stamp the new version.
- Spot-check classification of a few real fleet commands against the intended tier
  (conservative round-up, SEC-3).

## 5. Drift and credentials

- Run `drift_scan` per host; confirm critical findings (ssh_config,
  file_integrity) are triaged, not stale.
- Review outstanding credential grants (`CredentialBroker`): each should be
  least-privilege and still needed; revoke the rest. The broker gates actuation as
  a HARD audited precondition once any grant exists (ADR-0016, BL-049).
- Confirm the kill switch works: call `emergency_stop`, verify the denial of a
  follow-up call and the audit records, then restore out-of-band (remove the
  `PRAXIS_KILL_SWITCH_PATH` sentinel and restart) (ADR-0016, BL-075).
