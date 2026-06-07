---
name: audit-verification
description: Verify the tamper-evident audit log: recompute the per-entry hash chain and the Merkle root, and detect any break.
kind: tool
---

# Audit verification

Tool skill. Verifies the integrity of the append-only audit log: recomputes the
per-entry hash chain (`verify_chain`) and the periodic Merkle root, and reports
the first break if any record was inserted, deleted, or edited. The audit stores
only the output hash and length, never bodies, so verification needs no secret
material.
