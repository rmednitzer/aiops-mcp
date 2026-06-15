# praxis

**The unified AI-operations MCP.** A self-contained, security-first,
single-operator-operable, EU-sovereign control plane that fuses three things into one
audited surface.

!!! warning "Maturity"
    v0: real and tested, in iterative security hardening, not a finished product.
    `make ci-success` is green and each of the nine invariants has a passing test, but
    read [Limitations](https://github.com/rmednitzer/aiops-mcp/blob/main/LIMITATIONS.md)
    and the [security model](https://github.com/rmednitzer/aiops-mcp/blob/main/SECURITY.md)
    before relying on it.

## What it is

1. **A live bitemporal model of the fleet.** Hosts, services, packages, storage,
   networks, identities, and alerts as typed vertices and edges, every fact carrying four
   timestamps and never deleted (corrections supersede). The source of truth.
2. **A drift engine.** Observed host state against desired state (an IaC plan, a config
   baseline, or an operator-blessed known-good snapshot), with structured findings and
   human-gated convergence.
3. **A tiered, audited actuator.** One execution path that classifies every action T0 to
   T3, gates state-changing actions behind human confirmation, and wraps the right tool
   per host type (ssh, ansible, opentofu, runbooks, talosctl, redfish, cloud) instead of
   reinventing it.

It is self-contained: no imports from, or runtime coupling to, any sibling fleet
repository. Third-party libraries are minimal and license-vetted (pydantic for input
validation, psycopg for the optional Postgres backend), and the execution core stays
dependency-free.

## The nine invariants

The load-bearing controls, each with a proving test:

1. Single audited execution path; no tool bypasses it.
2. Tiered authority T0 to T3; conservative classification; modes gate tiers; deny is
   global.
3. Audit stores `output_sha256` and `output_len`, never bodies; an append-only hash
   chain; redacted parameters; the logger never raises.
4. Bitemporal, append-only state; deletion blocked at the store; supersession carries an
   actor and a reason.
5. host_type gates actuation; never SSH a Talos host.
6. DRY_RUN, then human approval, then execute; T3 needs a typed token and one target at a
   time.
7. stdio by default; HTTP needs a token, a non-loopback opt-in, and an SSRF egress filter;
   no token passthrough.
8. Lethal-trifecta containment; read tools separable from act tools; a human gate between
   observation and actuation.
9. Least privilege; scoped, revocable credentials; a kill switch; no `NOPASSWD: ALL`.

## Where to start

- [Architecture](architecture.md): the design reference and the layered structure.
- [Decisions (ADRs)](adr/README.md): the immutable record of every design decision.
- [Safety and security (STPA)](stpa/README.md): the hazard analysis and the security
  constraints each control traces to.
- [Governance](governance/compliance-map.md): the EU AI Act, NIS2, CRA, GDPR, and ISO
  27001 mapping.
- [Runbooks](runbooks/operate.md): the day-to-day operator loop.
- [Roadmap](roadmap/iam-access-and-secrets-expansion.md): documented possible future
  expansion.
- [Backlog](backlog.md): the stable `BL-NNN` work items.

The quickstart, the security model, and the running limitations live in the repository:
[README](https://github.com/rmednitzer/aiops-mcp#readme),
[SECURITY](https://github.com/rmednitzer/aiops-mcp/blob/main/SECURITY.md),
[LIMITATIONS](https://github.com/rmednitzer/aiops-mcp/blob/main/LIMITATIONS.md).

## License

Apache-2.0 (see `LICENSE` and `NOTICE` in the repository).
