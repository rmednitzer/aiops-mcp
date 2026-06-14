# ADR-0030: RFC 3161 stamper implementation (2026-06-14)

## Status

Accepted

## Date

2026-06-14

## Authors

praxis maintainers (ratifies ADR-0029; closes BL-095, from ADR-0019)

## Context

ADR-0029 proposed the non-forgeable checkpoint stamper design (RFC 3161 timestamp
authority behind an optional `tsa` extra, egress via the BL-046 resolver, fail-closed
verification) and was recorded Proposed because it adds a dependency and chooses
between RFC 3161 and Rekor. The maintainer ratified RFC 3161 plus the `tsa` extra. This
wave implements it and closes BL-095.

## Decision

1. Ratify ADR-0029 as the design of record, unchanged. This ADR carries the accepted
   status and the implementation; ADR-0029 keeps a ratification note (the ADR-0024 then
   ADR-0028 pattern).

2. Implement `Rfc3161Stamper` in `src/praxis/audit/rfc3161.py` with `asn1crypto` (the
   TSP/CMS ASN.1 models) and `cryptography` (signature and certificate verification),
   behind the optional `tsa` extra. The extra's libraries are imported lazily inside
   the class, so the module and the default `LocalStamper` still import without the
   extra and the execution core stays dependency-free. The `tsa` extra is pulled into
   the `dev` lock so CI exercises and covers the code.

3. `stamp()` builds a DER `TimeStampReq` (SHA-256 imprint, random 64-bit nonce,
   `certReq`), sends it through an injectable transport (the default is an SSRF-pinned
   HTTPS POST through `resolve_and_assert_egress_allowed`, the first live consumer of
   the BL-046 egress filter), then requires `status=granted`, the response nonce to
   equal the request nonce, and the `TSTInfo` imprint to equal the digest, and stores
   the token (base64 DER) with its `gen_time`. `verify()` is fail-closed: it re-parses
   the token, requires the imprint to equal the digest, requires the CMS signed
   attributes (content-type `tst_info` and a message-digest equal to the hash of the
   eContent), and verifies the signer's signature over the `SET OF` signed attributes
   against the configured TSA certificate's public key (RSA PKCS#1 v1.5 or ECDSA, hash
   from the signer's digest algorithm), with `gen_time` inside the certificate validity.
   Any parse, decode, or crypto error returns `False`.

4. `select_stamper(tsa_url, tsa_cert_path)` returns the RFC 3161 stamper when a TSA is
   configured and the `LocalStamper` otherwise, failing closed at startup if a URL is
   set without its certificate or without the extra (no silent downgrade of a security
   control). It is wired into the `EvidenceScheduler` in `build_context`; the config
   knobs are `PRAXIS_TSA_URL` and `PRAXIS_TSA_CERT` (a PEM signing certificate).

5. Tested offline: the suite generates a self-signed TSA certificate and signs RFC 3161
   tokens itself (the inverse of `verify`), then drives the stamper through a faked
   transport, covering the round trip and the fail-closed cases (wrong digest, tampered
   token, foreign signer, missing certificate, malformed token, and the rejection /
   nonce / imprint stamp failures). Only the SSRF-pinned socket I/O and the
   missing-extra import guard are uncovered (`pragma: no cover`); the egress decision is
   covered by the BL-046 tests.

6. The interim control is unchanged: with no TSA configured, the default offline
   `LocalStamper` is used and OS append-only storage on the audit, evidence, and anchor
   files remains the documented required control (SECURITY.md, ADR-0019). With a TSA
   configured, the stored token is non-forgeable by an evidence-file writer.

## Consequences

Positive: checkpoints can carry a timestamp an evidence-file writer cannot forge,
offline-verifiable against the TSA certificate; the feature is opt-in and the core and
default install stay dependency-free; the BL-046 egress filter gains its first real
consumer; the whole path is unit-tested offline.

Negative: a real anchor depends on an external TSA being reachable and trusted and on
the operator installing `praxis[tsa]` and configuring a certificate; `cryptography` is a
compiled dependency in the optional extra; the CMS verification is wired in-repo (on top
of vetted `asn1crypto` models and `cryptography` primitives), so it is covered by tests
rather than delegated to a dedicated TSP library; the trust anchor is a single pinned
TSA certificate, not full chain validation to a configured root.

Neutral: the `Stamper` Protocol and the `LocalStamper` default are unchanged; a
`RekorStamper` could be added beside `Rfc3161Stamper` under the same Protocol if a
transparency-log anchor is later wanted.

## Alternatives considered and rejected

- A dedicated RFC 3161 client library (for example `rfc3161ng`) instead of wiring CMS
  verification on `asn1crypto` + `cryptography`. Rejected to match the ratified ADR-0029
  dependency choice and to keep the extra to two mainstream, license-clean libraries;
  the verification wiring is small and fully tested, including tamper cases.
- Full certificate-chain validation to a configured root CA. Deferred: pinning the TSA
  signing certificate fits the single-operator posture and is simpler to reason about; a
  chain-validation mode is a revisit trigger.
- Verifying only the imprint and trusting the stored token. Rejected: an attacker could
  then substitute a self-signed token with the right imprint, so `verify` must check the
  TSA signature against the configured certificate.

## Revisit triggers

- A TSA that signs the eContent directly without signed attributes (needs a
  direct-eContent verification path).
- A need for full certificate-chain validation to a configured trust root.
- A transparency-log anchor (add a `RekorStamper` under the `Stamper` Protocol).
- Signature algorithms beyond RSA PKCS#1 v1.5 and ECDSA with the SHA-2 family.
