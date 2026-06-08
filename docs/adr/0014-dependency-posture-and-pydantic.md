# ADR-0014: Dependency posture, and pydantic at the external-input boundary

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-08      |
| Authors | Roman Mednitzer |

## Context

ADR-0001's "self-contained monorepo" rule was written at bootstrap to keep praxis
decoupled from the sibling fleet repositories: it must not import from, or take a
runtime dependency on, any other repository. That rule is sound and stays. It was
sometimes read more strongly, as "no third-party dependencies at all" or "implements
everything itself," which is not the actual constraint. The repository already
declares a third-party optional dependency (`psycopg`) for the Postgres backend, and
praxis is Apache-2.0, compatible with permissively-licensed libraries.

The over-absolute reading shaped the external-input boundary: each MCP tool kept a
hand-authored JSON Schema dict separate from its hand-written argument parsing, and
those two can drift; the same class of untrusted-input defects hardened by hand in
ADR-0013 (UTF-8 boundaries, finite numbers, size caps, duplicate keys) would be
expressed more safely and once if validation were declarative.

## Decision

1. Clarify the self-contained rule: it forbids coupling to any sibling fleet
   repository (no imports from, and no runtime dependency on, another repo), not the
   use of well-licensed third-party PyPI libraries. Third-party runtime dependencies
   are permitted under license and supply-chain review, kept minimal, pinned, and
   surfaced in the SBOM and dependency-audit CI jobs.
2. Adopt pydantic (MIT) as a core runtime dependency for declarative validation at
   the external-input trust boundary: the MCP tool arguments, the server
   configuration, and the SKILL.md frontmatter. A typed model is the single source of
   truth for both the advertised JSON Schema and the parse/validate step, removing the
   schema-versus-parser drift and making boundary validation fail-closed (unknown tool
   arguments are rejected, `extra='forbid'`).
3. Keep the execution core (`patterns`, `policy`, `redaction`, `audit`, `contract`,
   `runner`) and the fact model dependency-free. They are the sole security-review
   surface and take on no library; the SKILL.md hardened parser (ADR-0013, BL-057) is
   retained and pydantic validates its result, it does not replace it.
4. Record the clarification as an appended audit note on ADR-0001 (immutable) and
   supersede the over-absolute reading here.

## Consequences

Positive: one source of truth for each tool's schema and validation, so they cannot
drift; declarative, fail-closed validation at the trust boundary, which generalises
the ADR-0013 untrusted-input hardening; and the dependency posture is now stated
accurately across the docs. The execution core stays dependency-free.

Negative: the default install now pulls `pydantic` plus the compiled `pydantic-core`
wheel, a supply-chain item to vet, pin (`pydantic>=2,<3`), and SBOM. This is mitigated
by confining pydantic to the boundary and keeping the core clean.

Neutral: `psycopg` remains an optional extra; the default SQLite-over-stdio path still
needs no external services. The committed `docs/schema/*.json` are now generated from
the models rather than hand-authored.

## Alternatives considered and rejected

- Dev-only schema generation: use pydantic only to generate the committed schemas
  while runtime validation stays stdlib. Rejected: it leaves the security-relevant
  runtime parsing hand-rolled and makes validation behaviour differ by install.
- Keep hand-rolled validation. Rejected: the schema-versus-parser drift and the
  recurring untrusted-input bug class are exactly what a validation library removes.
- Pull validators or models from a sibling repository. Rejected: that would breach the
  self-contained rule, which this ADR clarifies but upholds.

## Revisit triggers

- The HTTP transport lands (BL-012): external JSON request bodies extend the boundary
  pydantic now covers, and a request/response model layer should follow.
- A pydantic major (v3) or a supply-chain advisory forces a pin change.
- The runtime dependency footprint grows beyond pydantic plus the optional psycopg
  without a superseding ADR.
