# ADR-0019: Runtime evidence production and the anchored high-water mark

## Status

Accepted

## Date

2026-06-12

## Authors

praxis maintainers (second remediation wave of 2026-06-12, following ADR-0018)

## Context

ADR-0008 designed a layered evidence model over the audit log: a per-entry hash
chain, periodic Merkle checkpoints, RFC 3161 stamping, and an optional
transparency-log anchor. ADR-0015 found, and the documentation honesty pass
recorded, that the running server produced none of it beyond the hash chain: the
checkpoint and verification code existed as a library (`audit/evidence.py`,
hardened in BL-037) but nothing invoked it at runtime (BL-076, the largest open
item in the final report of the ADR-0017 audit). Separately, BL-050 tracked the
one attack the per-file checks cannot see: an attacker who rewrites BOTH the
audit log and the evidence file to a shorter, internally consistent history
verifies clean, because every check derives from those same two files.

BL-076 bundles three asks: produce checkpoints from the running server, implement
a non-forgeable stamper, and document operating-system append-only storage as a
required control until then. The first and third are implementable and testable
self-contained; the second requires an ASN.1/TSP client and a network TSA, which
the dependency posture (ADR-0014) wants behind an optional extra and the SSRF
egress filter, and which cannot be verified in this environment. Following the
BL-054/BL-068 split precedent, that part becomes its own item.

## Decision

1. Runtime checkpointing (BL-076). `EvidenceScheduler` (`audit/evidence.py`) is
   wired as the AuditLogger's new optional post-record hook: every
   `PRAXIS_EVIDENCE_EVERY` records (default 64; an unparseable value degrades to
   64, never to disabled; explicit `0` disables) it runs `make_checkpoint` over
   the audit file into `PRAXIS_EVIDENCE_PATH` (default `<audit>.evidence.jsonl`,
   matching the verifier's existing default). `serve` finalizes the scheduler in
   a `finally`, so an orderly shutdown (stdin EOF, or the staged-HTTP refusal
   path) covers the audit tail and `verify_evidence`'s full-coverage rule holds
   at rest. A crash leaves an uncovered tail that verification flags: the
   intended visible seam, not silent loss. Production is wired only when an
   audit file is configured; a stderr-degraded logger produces no evidence.

2. Containment. The hook runs after the record is written and the lock released,
   and both the hook call (in the logger) and the checkpoint body (in the
   scheduler) contain every exception to a stderr warning with the interval
   reset, so evidence production can never lose, block, or break an audit record
   (invariant 3; the hash chain remains the primary record). The scheduler
   serialises under its own lock, mirroring the audit writer (BL-029).

3. Anchored high-water mark (BL-050). With `PRAXIS_ANCHOR_PATH` set, each
   checkpoint head (`seq`, `tree_size`, `root_sha256`, `checkpoint_hash`) is
   appended to an owner-only, `O_APPEND` anchor file. `verify_evidence` gains an
   optional `anchor_path`: the latest anchored head must name a checkpoint that
   exists, hash-identical, in the already-verified evidence chain. Evidence
   truncated or regrown below the anchored high-water mark fails; so does a
   configured-but-missing or empty anchor while checkpoints exist (fail closed;
   an absent anchor over zero checkpoints is genesis and verifies, which also
   defines the adoption seam: enabling the anchor on an existing deployment
   reports missing until the first new checkpoint anchors). The anchor's value
   rests on the operator placing it on a different trust domain than the audit
   log; the systemd unit and runbook now say so. `verify_audit.py` takes the
   anchor as an optional third argument.

4. Snapshot hashes are Merkle-committed (BL-030). Since BL-085 every ingest
   writes an audit record carrying `raw_sha256`/`raw_len` of the collected
   telemetry; with checkpoints now produced at runtime, each collected
   snapshot's hash is committed under a verified Merkle root by construction. A
   test ingests through the registered tool, finalizes, and verifies the
   covering checkpoint over the record carrying the hash. No separate
   per-snapshot checkpoint field is needed; the 2011-era item is satisfied by
   composition.

5. The non-forgeable stamper is split out as BL-095 (open): a real RFC 3161 TSP
   client behind an optional extra and the SSRF egress filter, or a
   transparency-log anchor (Rekor). Until it lands, the default `LocalStamper`
   remains keyless self-attestation, and operating-system append-only storage
   (`chattr +a` or WORM) on the audit, evidence, and anchor files is the
   documented, required deploy control against an attacker who can rewrite them
   (SECURITY.md, LIMITATIONS.md, the self-audit runbook, and the systemd unit
   all state this). BL-076, BL-050, and BL-030 are resolved by this wave.

## Consequences

Positive:

- The evidence layer is no longer aspirational: a default deployment with an
  audit file produces verifiable Merkle checkpoints with no operator action, and
  the BL-050 truncate-both-files attack is detectable once an anchor is placed
  off-host. The tamper matrix in the tests now covers exactly that attack, both
  without the anchor (passes, documenting the gap) and with it (fails closed).
- Verification at rest is meaningful: full coverage is enforced after orderly
  shutdown, and the runbook documents the two expected seams (crash tail,
  anchor adoption).

Negative:

- `make_checkpoint` re-reads the whole log and recomputes the Merkle tree each
  time, so cumulative cost grows quadratically over the log size divided by the
  interval. At single-operator volumes (the v0 target) this is negligible; a
  high-volume deployment should raise `PRAXIS_EVIDENCE_EVERY` until an
  incremental tree lands.
- Two new files appear next to the audit log by default (evidence; anchor only
  when configured), and the audit-adjacent disk footprint grows by one
  checkpoint line per interval.

Neutral:

- New config fields (`evidence_path`, `evidence_every`, `anchor_path`) are
  additive with safe defaults; `AuditLogger` gains an optional constructor
  kwarg; `ServerContext` gains an optional `evidence` field. The L1 surfaces
  extend additively per the stability rule.
- The MCP tool surface is unchanged; no schema regeneration.

## Alternatives considered and rejected

- A background timer thread instead of a per-N-records hook. Rejected: a timer
  adds a thread and shutdown ordering to the security-critical path for no
  determinism gain; record count is deterministic, testable, and idle-quiet (an
  idle server writes no records and needs no checkpoints).
- A supervised sidecar producing checkpoints out of process (the BL-076
  alternative). Rejected for v0: it doubles the deployment surface and the
  sidecar needs its own audit; in-process production with contained failure
  keeps the single-operator deployment self-contained. A sidecar remains the
  right shape if checkpointing cost ever needs isolation.
- Anchoring every audit record rather than checkpoint heads. Rejected: that
  duplicates the log onto the second trust domain; the high-water mark needs
  only the head to pin history below it.
- Failing verification when the anchor lags the evidence by more than one head.
  Rejected: anchor-write failure is already warned and surfaces as a stale
  high-water mark; the security property (no truncation below the anchored
  head) holds regardless of lag.

## Revisit triggers

- BL-095 lands (non-forgeable stamper), which upgrades checkpoints from
  integrity-against-accident to attacker-grade evidence and may justify
  enabling anchor-by-default.
- Log volume grows to where the quadratic re-read cost matters: switch to an
  incremental Merkle tree (RFC 6962 consistency proofs) and append-time leaf
  hashing.
- The HTTP transport (BL-012) brings multi-process serving: the scheduler and
  the audit writer both assume one process owns one file set.
