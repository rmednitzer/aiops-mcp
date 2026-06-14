# ADR-0029: Non-forgeable checkpoint stamper: RFC 3161 timestamp authority (2026-06-14)

## Status

Proposed

## Date

2026-06-14

## Authors

praxis maintainers (design decision for BL-095, requested before implementation)

## Context

The evidence layer stamps each Merkle checkpoint with a `Stamper`
(`src/praxis/audit/rfc3161.py`). The default `LocalStamper` is self-contained and
offline: its token is `{"tsa": "local", "digest": <root>, "ts": <utc>}`. That token is
**forgeable by anyone who can write the evidence file**: there is no secret, so an
attacker who rewrites the audit log, recomputes the Merkle root, and re-emits a
matching local token defeats `verify_evidence`. BL-076 closed runtime evidence
production and the anchored high-water mark (ADR-0019), but explicitly left the
non-forgeable stamper open as BL-095; until it lands, OS append-only storage
(`chattr +a` / WORM) on the audit, evidence, and anchor files is the documented
required control (SECURITY.md, ADR-0019).

The pieces are already in place: the `Stamper` Protocol (`stamp`/`verify`, both
returning JSON-serializable values and fail-closed) is stable; `Rfc3161Stamper` exists
as a stub that raises; the SSRF egress primitive `resolve_and_assert_egress_allowed`
(ADR-0025, BL-046) is ready and has no consumer yet; the optional-extra pattern is
established (`postgres`). The constraints are the project's: the execution core stays
dependency-free, third-party libraries are minimal and license-vetted (ADR-0014), the
default install must keep working offline with zero new dependencies, the egress path
must be SSRF-filtered with no token passthrough, and any verification must be
fail-closed. The deployment posture is EU-sovereign and single-operator-operable.

This ADR decides the approach so the implementation (the remaining BL-095 work) can
proceed against a ratified design. It is recorded Proposed for ratification because it
adds a third-party dependency (an ADR-0014 posture decision) and chooses between two
trust anchors with real trade-offs.

## Decision (proposed)

1. **Implement RFC 3161 timestamping** (a qualified external timestamp authority) as
   the non-forgeable `Rfc3161Stamper`, keeping `LocalStamper` the default and the
   execution core dependency-free. An RFC 3161 token is a CMS `SignedData` over a
   `TSTInfo` signed by the TSA's private key, so it cannot be forged by someone with
   write access to the evidence file (the BL-095 threat), and it is verifiable offline
   by any auditor against the TSA certificate with standard tools (`openssl ts`). RFC
   3161 fits the EU-sovereign, single-operator posture: the operator points at an
   eIDAS-qualified or self-hosted TSA, with no dependency on a public transparency-log
   ecosystem.

2. **Dependency**: a new optional `tsa` extra. Proposed members: `asn1crypto` (MIT;
   pure-Python ASN.1 with `tsp`/`cms` models for `TimeStampReq`/`TimeStampResp`/
   `TSTInfo`) and `cryptography` (Apache-2.0/BSD; the signature and certificate
   verification). Both are widely used and license-clean. The core and the default
   install gain nothing; `Rfc3161Stamper` is selected only when the operator installs
   `praxis[tsa]` and configures a TSA, exactly as `postgres` gates psycopg.

3. **`stamp(digest_hex)`**: build a DER `TimeStampReq` for the SHA-256 message imprint
   with a random nonce and `certReq=true`; POST it (`application/timestamp-query`) to
   the configured TSA URL through `resolve_and_assert_egress_allowed` (HTTPS only, the
   host vetted and the connection pinned to a vetted IP, a bounded response size and
   timeout, no credentials in the URL). Parse the `TimeStampResp`, require
   `status=granted`, the response nonce to equal the request nonce, and the `TSTInfo`
   message imprint to equal `digest_hex`. Store the token as
   `{"tsa": "rfc3161", "digest": digest_hex, "token_b64": <base64 DER token>, "gen_time": <TSTInfo genTime>}`,
   keeping the dict JSON-serializable for the checkpoint. On any network, status,
   nonce, or imprint failure, `stamp` raises (the caller already contains failures).

4. **`verify(digest_hex, token)`**: fail-closed. Decode `token_b64`, parse the CMS
   `SignedData`/`TSTInfo`, require the imprint to equal `digest_hex`, and verify the
   TSA signature over the `TSTInfo` against the operator-configured TSA certificate
   (and that `gen_time` is within the certificate validity). Any missing field, parse
   error, imprint mismatch, or signature failure returns `False`. Without the `tsa`
   extra or a configured certificate, `verify` returns `False` and the stamper is
   simply not selected (`LocalStamper` remains the default).

5. **Egress wiring**: this is the first server-initiated egress consumer, so it wires
   `resolve_and_assert_egress_allowed` into a live path, advancing BL-046's open
   "wire into the egress path" half. The TSA URL is operator-configured
   (`PRAXIS_TSA_URL`); a non-HTTPS or unresolvable/blocked host fails closed and the
   stamp is refused (the operator falls back to `LocalStamper` plus OS append-only).

6. **Interim control unchanged**: until a TSA is configured, OS append-only storage on
   the audit, evidence, and anchor files remains the documented required control
   (SECURITY.md, ADR-0019). This ADR does not weaken any default; it adds an opt-in,
   stronger anchor.

7. **Offline test strategy** (so the change meets the render-before-claim bar without a
   live TSA): unit-test the `TimeStampReq` DER encoding and the `TimeStampResp` parsing
   against captured fixtures; test `verify` with a fixture TSA certificate and a token
   it signed (a real imprint match passes, a flipped digest and a truncated token both
   fail closed); test the network path with a fake transport and a fake resolver
   (a blocked host refuses; a 200 with a granted response succeeds). No live TSA in CI.

## Consequences

Positive: checkpoints gain a timestamp an evidence-file writer cannot forge, closing
the BL-095/BL-076 residual; the token is independently verifiable offline against the
TSA certificate; the default install is unchanged and still offline; the optional
extra keeps the core dependency-free (ADR-0014); BL-046's resolver gets its first real
consumer with the SSRF filter on the path.

Negative: a real anchor now depends on an external TSA being reachable and trusted, and
on the operator installing `praxis[tsa]` and configuring a certificate; a stamp made
while the TSA is unreachable falls back to the forgeable local path (the interim
control still applies). RFC 3161 verification pulls `cryptography`, a compiled
dependency, into the optional extra. The implementation parses untrusted TSA responses,
so the parser is an attack surface (mitigated by using `asn1crypto`'s vetted models, a
bounded response size, and fail-closed verification).

Neutral: the `Stamper` Protocol and the `LocalStamper` default are unchanged; this only
makes the existing `Rfc3161Stamper` real behind the extra. Rekor remains a viable
alternative anchor if a transparency-log model is later preferred; the Protocol admits
a `RekorStamper` beside `Rfc3161Stamper` without further change.

## Alternatives considered and rejected

- **Rekor transparency log** (sigstore). Rejected as the default for this context: it
  binds the anchor to the public sigstore ecosystem (or a self-hosted Rekor plus its
  operational burden), which is a weaker fit for an EU-sovereign, single-operator tool
  than pointing at an eIDAS-qualified or internal TSA. RFC 3161 tokens are also
  offline-verifiable with ubiquitous tooling. Rekor stays admissible behind the same
  Protocol if wanted later.
- **Hand-rolled ASN.1** with no library. Rejected: hand-parsing an untrusted TSA
  `TimeStampResp`/CMS `SignedData` is a needless, error-prone attack surface when
  `asn1crypto` provides vetted models; the project is dependency-minimal, not anti-PyPI
  (ADR-0014), and the parser only ships in the optional extra.
- **A keyed local stamper** (HMAC with a key outside the evidence file, or a KMS).
  Rejected as the BL-095 answer: it is better than the keyless `LocalStamper` but the
  time is still self-asserted, not qualified external time, and a key co-located with
  the operator is a weaker non-repudiation story than a TSA signature. It remains a
  reasonable future `Stamper` for an air-gapped site with a hardware key, but it is not
  what BL-095/BL-076 asked for.
- **Verify the signature only offline, store the token unverified at stamp time.**
  Rejected: `verify_evidence` must be able to fail closed on a bad token during a
  self-audit, so `verify` must do real signature verification when the extra and the
  certificate are present, not merely re-check the imprint.

## Revisit triggers

- Ratification of this ADR (then the implementing change closes BL-095).
- A decision to prefer a transparency-log anchor (add a `RekorStamper` beside the RFC
  3161 one under the same Protocol).
- An eIDAS or TSA-certificate-handling requirement that needs full path validation to a
  configured trust root beyond a single configured TSA certificate.
- `cryptography` or `asn1crypto` posture concerns (size, build, advisories) that would
  push toward a lighter ASN.1 path.
