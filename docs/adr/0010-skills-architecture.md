# ADR-0010: Skills architecture

| Field   | Value           |
|---------|-----------------|
| Status  | Accepted        |
| Date    | 2026-06-07      |
| Authors | Roman Mednitzer |

## Context

The prototype's skills were flat markdown files an operator grepped by hand. There
was no router, so the right knowledge surfaced only if the operator remembered it
existed, and no separation between "knowledge about a host" and "a procedure for
operating a tool". A model-driven plane needs the right skill selected
precisely and safely, and an untrusted bundle must not be able to execute code on
load.

## Decision

1. Two skill kinds, kept distinct:
   - host-knowledge skills ("what is"): facts and context about a host or
     subsystem (read-only knowledge).
   - tool skills ("how to operate"): procedures for operating a tool or running a
     runbook (still routed through the executor for any host action).
2. A skill is a bundle: `SKILL.md` with YAML frontmatter (`name`, a precise
   `description` a router can select on, kind, inputs/outputs) plus optional
   `references/`. The description must be specific enough that the router picks it
   without ambiguity.
3. A registry discovers bundles; a routing-chain dispatcher selects a skill from a
   query (cheap matchers first, falling through to costlier ones), with per-link
   failure containment so one bad matcher cannot abort routing.
4. Untrusted bundles load with `allow_contract=False`: no bundle-supplied code
   runs on load. Any executable contract is opt-in and runs only through the
   isolated execution path, never implicitly.
5. An evaluation gate measures dispatch quality (P@1 and MRR) against a golden
   set, and a schema-drift guard checks the generated skill-manifest schema in CI.
   A routing regression fails the build.

## Consequences

Positive: the right skill is selected by description, not by recall; knowledge and
procedure are not conflated; an untrusted bundle is inert on load; routing quality
is measured and regression-gated.

Negative: skill authors must write a precise, router-targetable description; a
vague one degrades P@1 and the eval gate will catch it.

Neutral: the routing chain is extensible (new matchers added beside the old ones,
additive per the stability rule).

## Alternatives considered and rejected

- A single flat skill list grepped at query time. Rejected: no precision, no
  separation of knowledge from procedure, and the prototype proved it does not
  scale.
- Executing bundle code on load for "smart" skills. Rejected: that hands an
  untrusted bundle arbitrary code execution; contracts are opt-in and isolated.

## Revisit triggers

- The skill count outgrows the routing-chain dispatcher's precision.
- A semantic (embedding) router is needed beside the lexical chain.
