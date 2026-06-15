# Roadmap: IAM, access control, and secrets (possible future expansion)

## Status and how to read this

Exploratory. This is a forward-looking design study, not a decision and not a commitment.
Nothing here is built, and nothing here changes the current posture. It exists to record,
in detail, what an advanced identity, access-management, and secrets layer would look like
if `praxis` ever moves beyond its single-operator target, so that the move (if it comes) is
made against vetted patterns rather than invented under pressure.

ADRs record decisions; this is not one. When a phase below is actually scheduled, it is
promoted to a new ADR (which may supersede ADR-0006's auth posture) plus `BL-NNN` backlog
items, following the standing governance flow (ADR then backlog then code). Until then this
file is the canonical "what if" reference, linked from `LIMITATIONS.md`.

The study was grounded in trusted public sources, cross-checked across them, validated
against the patterns those sources call known-good, and tested adversarially against the
nine invariants. See the References section for the sources; the Adversarial analysis
section for the assumptions that were stress-tested.

## TL;DR value verdict

- For the current target (single-operator, EU-sovereign, self-contained, dependency-minimal),
  advanced IAM/RBAC/ABAC is **not needed and would be net-negative**: it adds heavy
  dependencies and external infrastructure (an identity provider, a policy engine, a secrets
  backend) against the ADR-0001/ADR-0014 posture, for authority a single operator already has.
- The current model is **not deficient** for that target. Cross-checking against the MCP
  authorization specification and its security best practices shows `praxis` already meets the
  load-bearing controls (no token passthrough, default-closed HTTP, audience-less single-token
  auth with a non-loopback opt-in, SSRF egress, per-session consent ceiling, tiered authority,
  a human-binding JIT approval, and a single audited path). This roadmap is therefore an
  **expansion**, not a remediation.
- The expansion becomes **high value** only on a specific trigger: a multi-operator, team,
  multi-tenant, or regulated-enterprise deployment, where per-principal identity, least
  privilege per operator, and per-principal auditability are required by NIS2 Art. 21 and
  ISO 27001 A.5.15/A.5.16/A.5.18.
- It is **cleanly additive**: the MCP resource-server model lets `praxis` gain per-principal
  identity without becoming an identity provider, the NIST 800-207 policy-decision/enforcement
  split lets the existing executor stay the single enforcement point, and the credential broker
  already separates the authorization record from secret material. Every phase can stay
  default-closed and keep the execution core dependency-free.

## Baseline: what praxis enforces today

This is the ground truth the roadmap builds on (see `SECURITY.md`, ADR-0004, ADR-0005,
ADR-0006, ADR-0016, ADR-0041).

- **Authentication.** stdio relies on local process trust (the MCP-recommended model for
  stdio: retrieve credentials from the environment, do not run the HTTP auth flow). HTTP uses a
  single shared bearer token (`PRAXIS_HTTP_TOKEN`), constant-time compared, plus a non-loopback
  opt-in and an SSRF egress filter, and never forwards the token upstream (no passthrough).
- **Authorization (capability-based, not principal-based).** Server modes (`readonly`,
  `guarded`, `open`) gate which of T0 to T3 is reachable; every action is classified T0 to T3
  with conservative rounding and a global, unconditional deny list. A per-session consent
  ceiling (ADR-0041) caps a session at or below the mode.
- **JIT admission.** A gated dry run mints a single-use, TTL-bound approval nonce surfaced
  out-of-band on the operator console; the real run must present it. T3 requires exactly one
  target. The trifecta latch escalates: once untrusted content is ingested, any T1+ real run
  needs a minted approval (invariant 8).
- **Scoped credentials (primitive ABAC).** `CredentialBroker` holds least-privilege grants
  naming role, exact hosts, and a max tier, independently revocable, with a global `kill_all`.
  It is opt-in (zero grants means the single-operator default with no scope gate) and holds the
  authorization record only: the actual secret material is injected out-of-band and never
  stored or logged.
- **Audit.** Every call writes one record into an append-only hash chain, carrying optional
  `request_id` / `client_id` correlation (ADR-0038) and never the output body.

The gaps are scope boundaries, not bugs: a single shared token (no per-principal identity),
consent and broker keyed to session/handle rather than identity, no externalized policy
engine, secret material external but not integrated with a dynamic-secrets backend, and no
workload identity for the `praxis`-to-fleet hop.

## Known-good patterns, cross-checked, and how they map

| Pattern (source) | What it prescribes | Mapping onto praxis |
|---|---|---|
| MCP authorization, 2025-11-25 | MCP server is an OAuth 2.1 **resource server** only, never the authorization server; MUST implement RFC 9728 Protected Resource Metadata, validate token audience (RFC 8707), require PKCE, return 401/403 with `WWW-Authenticate` scope guidance, and **MUST NOT accept or transit tokens issued for anything else** | `praxis` adopts the resource-server role on HTTP and keeps the identity provider external. Validates ADR-0006 Decision 3 (no passthrough) directly. The `client_id`/`sub` becomes the principal already carried in the audit chain |
| MCP security best practices | Token passthrough is forbidden; confused-deputy is mitigated by per-client consent | Already satisfied (no passthrough; per-session consent). Per-principal consent is the multi-operator extension |
| NIST SP 800-207 (Zero Trust) | Separate the Policy Decision Point (decision) from the Policy Enforcement Point (enforcement) to decouple security logic from application logic | The executor `run()` is already the single PEP (invariant 1). An optional, pluggable PDP can be added without moving enforcement |
| NIST SP 800-162 (ABAC) | RBAC and ACLs are special cases of ABAC (role and identity as attributes); pick the simplest model that meets the requirement | Start with RBAC (roles to tiers/hosts), already half-present in the broker; offer ABAC via policy-as-code only where a requirement demands it |
| SPIFFE / SPIRE | Workload identity as short-lived, auto-rotated SVIDs; no static secrets; attestation-based; revocation by expiry | Optional backend for the `praxis`-to-fleet and `praxis`-to-upstream hops, and for `praxis`'s own identity to an upstream auth server |
| Vault dynamic secrets / Zero Standing Privileges | Mint ephemeral, short-TTL credentials on request; auto-revoke; no standing access | A backend behind the existing broker: the broker holds the grant, the backend mints the material JIT |
| Policy-as-code (OPA/Rego, AWS Cedar) | Externalize authorization into versioned policy; Cedar covers RBAC+ABAC and is embeddable and formally analyzable | The optional PDP's policy language if ABAC is adopted; Cedar is the closer fit for an embeddable, dependency-bounded default |

## Design constraints (non-negotiable for any phase)

These follow directly from the nine invariants and ADR-0001/ADR-0014, and any future ADR
must honor them.

1. **Identity and authorization sit ABOVE the existing gates, never replace them.** A valid
   token, role, or policy `permit` never bypasses the global deny list, the tier gate, the
   human approval gate, the trifecta containment, or the audit write. Authz can only further
   restrict; the executor remains the single enforcement point (invariant 1).
2. **Default-closed and dependency-free core.** Every phase is opt-in. With it off, behaviour
   and the dependency set are unchanged. New libraries (a JWT verifier, a policy engine, a
   secrets client) live behind optional extras, never in the execution core (ADR-0001/0014).
3. **praxis is a resource server and a secrets consumer, never an identity provider or a
   secrets store.** The IdP and the secrets backend stay external and operator-run. This keeps
   the attack surface small and the deployment EU-sovereign (self-hostable IdPs: Keycloak,
   Authentik, Authelia, Zitadel).
4. **PDP inputs are trusted attributes only.** Any ABAC decision is computed over operator
   identity, role, host, tier, time, and request metadata. Collected host facts and command
   output are attacker-influenced (the threat model) and MUST NOT feed an authorization
   decision, or they become a privilege-escalation channel.
5. **Fail closed, everywhere.** An unreachable IdP, PDP, or secrets backend denies, audited. A
   network call added to the audited path is itself subject to the SSRF egress filter and a
   timeout, and never opens access on error.
6. **Additive-stability.** New auth modes, a PDP hook, and broker backends are new optional
   Protocols and parameters beside the existing surfaces, not changes to them (ADR shape rule).

## The phased roadmap

Phases are ordered by dependency and value. Each is independently shippable, opt-in, and
guarded by a promotion gate. None is started until its trigger fires.

### Phase 1: Per-principal identity on HTTP (OAuth 2.1 resource server)

- **Goal.** Replace "one shared token means one operator" with real per-principal identity on
  the HTTP transport, without `praxis` becoming an identity provider.
- **Standard.** MCP 2025-11-25 authorization: resource-server role; RFC 9728 Protected Resource
  Metadata at `/.well-known/oauth-protected-resource`; validate token audience (RFC 8707) so a
  token minted for another resource is rejected; 401 with `WWW-Authenticate` carrying
  `resource_metadata` and `scope`; PKCE is the client's responsibility.
- **In-repo.** An opt-in `PRAXIS_HTTP_AUTH=oauth` mode that validates a presented bearer JWT or
  opaque token against the operator's external authorization server (signature or introspection,
  audience, expiry, issuer), then binds the `sub`/`client_id` claim to the request's `client_id`
  for the audit chain (ADR-0038 already carries it). The static shared token stays the default
  for single-operator. JWT verification lives behind an optional extra.
- **External.** The authorization server (a self-hosted, EU-sovereign IdP).
- **Dependency impact.** None by default; an optional `oauth` extra (a JOSE/JWT verifier) when
  enabled.
- **Compliance.** NIS2 Art. 21 access control; ISO 27001 A.5.16 (identity management),
  A.5.17 (authentication information).
- **Adversarial.** Token theft and replay are bounded by short TTL plus audience binding; a
  compromised IdP is contained because the tier, deny, trifecta, and human gates still sit below
  authz (constraint 1). The token is still never forwarded upstream.
- **Promote when.** A second human operator (or a non-interactive client that must be told
  apart) needs to use the HTTP transport.

### Phase 2: Principal-keyed consent and RBAC roles

- **Goal.** Make the consent ceiling and the credential broker least-privilege per principal,
  not per session/handle.
- **Standard.** NIST RBAC (a role is an attribute; the simplest model first), expressed as MCP
  OAuth scopes mapped to roles and tiers, with the resource server emitting required scopes in
  the 403 `insufficient_scope` challenge for step-up authorization.
- **In-repo.** A role-to-(max tier, host scope) mapping, keyed by the Phase 1 principal; the
  consent ceiling and `CredentialBroker.authorized` consult the principal's role. This is the
  "externalize consent and tokens" revisit trigger named in ADR-0006.
- **External.** Role and scope assignment (in the IdP).
- **Dependency impact.** None beyond Phase 1.
- **Compliance.** ISO 27001 A.5.15 (access control), A.5.18 (access rights); NIS2 least
  privilege.
- **Adversarial.** Role explosion and over-broad roles are the classic RBAC failure; mitigated
  by keeping tiers as the hard ceiling (a role can never exceed the server mode) and by the
  existing T3 single-target rule. Scope-to-tier mapping is data, validated like the compliance
  catalog.
- **Promote when.** Operators need different authority (for example a read-only auditor and a
  break-glass operator).

### Phase 3: Optional externalized policy decision (ABAC / policy-as-code)

- **Goal.** Support attribute-based decisions for organizations whose policy cannot be expressed
  as roles plus tiers, without moving enforcement out of the executor.
- **Standard.** NIST SP 800-207 PDP/PEP split; policy-as-code (AWS Cedar as the embeddable,
  formally-analyzable default candidate; OPA/Rego as the external-service alternative).
- **In-repo.** A `PolicyDecision` Protocol consulted inside `run()` as an additional HARD
  precondition, beside (never instead of) the tier and deny gates. The default implementation is
  the current in-repo policy (no dependency, no behaviour change). An optional embedded Cedar
  PDP, or an external OPA call (SSRF-filtered, timed out, fail-closed), is selectable.
- **External.** The policy bundle (versioned, operator-authored), and optionally an OPA server.
- **Dependency impact.** None by default; an optional `policy` extra when an engine is enabled.
- **Compliance.** ISO 27001 A.5.15; auditable policy-as-code supports NIS2 evidence duties.
- **Adversarial.** This is the riskiest phase. The decisive constraint is number 4: the PDP sees
  only trusted attributes (principal, role, host, tier, time, request metadata), never collected
  facts, or an attacker who poisons a fact poisons an authorization decision. A network PDP adds
  latency and a fail-open hazard; it must time out and deny. The PDP can only deny further; a
  `permit` never widens past the tier/deny/human gates.
- **Promote when.** A concrete requirement cannot be met by Phase 2 roles plus tiers (for
  example "operator X may act on hosts tagged `staging` only between 08:00 and 18:00 UTC").

### Phase 4: JIT credential issuance (dynamic secrets behind the broker)

- **Goal.** Zero standing privileges for actuation: the broker mints ephemeral, short-TTL
  credentials per grant instead of relying on standing out-of-band material.
- **Standard.** Vault dynamic secrets and the Zero-Standing-Privileges pattern (mint on request,
  auto-expire, audit).
- **In-repo.** A `SecretSource` Protocol behind the existing broker: the broker still holds the
  authorization record (role, hosts, max tier), and the source mints the material JIT for the
  scope and TTL of the grant. The default stays out-of-band injection (today's behaviour).
- **External.** The dynamic-secrets backend (Vault, or a cloud secrets manager).
- **Dependency impact.** None by default; an optional `vault` extra when enabled.
- **Compliance.** ISO 27001 A.8.24 (use of cryptography / key management adjacency); NIS2 access
  control; strong support for incident containment (short-lived credentials expire).
- **Adversarial.** A compromised broker process could request material; bounded by the grant
  scope, the TTL, and `kill_all` tripping the kill switch. The secrets-backend call is
  SSRF-filtered and fail-closed. Material is still never written to the audit log (only its use
  is recorded).
- **Promote when.** Standing credentials on the host become an audit finding, or a deployment
  mandates zero standing privileges.

### Phase 5: Workload identity for praxis itself (SPIFFE/SPIRE)

- **Goal.** Give `praxis` a short-lived, attested workload identity for mTLS to upstreams (the
  IdP, the secrets backend) and, where applicable, to the fleet, removing static service
  credentials for `praxis` itself.
- **Standard.** SPIFFE SVIDs issued and rotated by SPIRE; revocation by expiry.
- **In-repo.** An optional mTLS client-identity source for `praxis`-initiated egress (still
  behind the SSRF filter); no change to the inbound MCP surface (that is Phase 1).
- **External.** A SPIRE deployment.
- **Dependency impact.** None by default; an optional extra.
- **Compliance.** NIS2 and ISO 27001 access control for machine identities; zero-trust posture.
- **Adversarial.** SVID misissuance is bounded by SPIRE attestation and short TTL; this phase
  reduces, not increases, the standing-secret surface. It does not touch the trifecta or the
  human gate.
- **Promote when.** A zero-trust deployment requires attested machine identity, or static
  service credentials for `praxis` become unacceptable.

## Adversarial analysis: assumptions tested

- **"praxis needs advanced IAM."** False for the current target. The product is single-operator
  and self-contained by design; adding an IdP, a policy engine, and a secrets backend imports
  infrastructure and dependencies for authority one operator already holds, and enlarges the
  attack surface that the lethal-trifecta posture works to keep small. Verdict: negative value
  now, conditional value later (see triggers).
- **"The current auth is weak."** Not against the relevant standard. The MCP authorization spec
  and its security best practices name token passthrough as the primary anti-pattern and per-
  client consent plus audience binding as the primary defenses; `praxis` already forbids
  passthrough, fails closed, filters SSRF, and gates per session. The shared-token limitation is
  a multi-operator scope boundary, not a control weakness for one operator.
- **"It can be bolted on cleanly."** True, with discipline. The resource-server model means no
  IdP in-tree; the PDP/PEP split means enforcement never leaves `run()`; the broker already
  separates record from material. The risk is dependency creep and a policy path that trusts
  attacker-influenced input; constraints 2 and 4 exist to prevent both.
- **"More access management always improves security."** False if it widens the trifecta blast
  radius or feeds authorization from collected data. Per-principal least privilege narrows blast
  radius (good); a network PDP or an external IdP adds availability and fail-open hazards
  (managed by fail-closed plus timeouts plus SSRF filtering); ABAC over collected facts would be
  a privilege-escalation channel (forbidden by constraint 4).
- **"Externalizing the PDP centralizes risk."** Partly true: the IdP and PDP become high-value
  targets. Mitigated by keeping the executor's deny/tier/human/trifecta gates as defense in depth
  below authz, so a compromised decision layer still cannot bypass the irreducible gates.

## Value assessment

- **Single-operator (today):** do not build. The cost (dependencies, external infrastructure,
  attack surface, operational burden) exceeds the benefit (none, for one operator).
- **Small team / multi-operator:** Phases 1 and 2 carry clear value (per-principal identity and
  least privilege, per-principal audit) at modest, opt-in cost.
- **Regulated enterprise / multi-tenant:** Phases 1 to 4 (and 5 for zero-trust) become
  load-bearing for NIS2 Art. 21 and ISO 27001 A.5.15 to A.5.18, and strengthen EU AI Act Art. 14
  human-oversight evidence by tying every gated action to a named principal.
- **Cross-cutting:** the work is standards-aligned and additive, so even partial adoption (just
  Phase 1) is coherent and reversible. The recommendation is to build strictly on trigger, one
  phase at a time, each behind its own ADR.

## Non-goals (what stays external, permanently)

- `praxis` is not an identity provider. Authentication of humans is delegated to an external,
  operator-run, EU-sovereign IdP.
- `praxis` is not a secrets store. It holds authorization records, never secret material.
- `praxis` does not replace its tiered authority, deny list, human approval gate, or trifecta
  containment with identity or policy. Those remain unconditional and below authz.
- No phase introduces a runtime dependency into the execution core or changes a default to open.

## Decision gates and governance

Each phase, when triggered, is promoted in this order: a new ADR (Phase 1 likely supersedes the
ADR-0006 auth posture for the multi-operator case, per its standing revisit trigger), then
`BL-NNN` backlog items with that ADR as their source, then code with the proving tests and the
STPA traceability the nine invariants require. New security constraints (for example "an
authorization decision never consumes collected facts") are added to `docs/stpa/` with an
enforcement mechanism and a test, exactly as existing constraints are. Until a trigger fires,
this document is the record and `LIMITATIONS.md` points to it.

## References

Trusted public sources used and cross-checked for this study (accessed 2026-06-15):

- Model Context Protocol, Authorization (2025-11-25): https://modelcontextprotocol.io/specification/draft/basic/authorization
- Model Context Protocol, Security Best Practices: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
- OAuth 2.1 (IETF draft): https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13
- RFC 9728, OAuth 2.0 Protected Resource Metadata: https://datatracker.ietf.org/doc/html/rfc9728
- RFC 8707, Resource Indicators for OAuth 2.0: https://www.rfc-editor.org/rfc/rfc8707.html
- NIST SP 800-207, Zero Trust Architecture: https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf
- NIST SP 800-162, Guide to Attribute Based Access Control (ABAC): https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-162.pdf
- SPIFFE / SPIRE (workload identity): https://spiffe.io
- HashiCorp Vault, dynamic secrets: https://developer.hashicorp.com/vault/tutorials/db-credentials/database-secrets
- Open Policy Agent (Rego): https://www.openpolicyagent.org and AWS Cedar: https://www.cedarpolicy.com
