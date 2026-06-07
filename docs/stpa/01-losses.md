# 01 Losses

Losses are the unacceptable outcomes the system exists to prevent. They are
stakeholder-level, not technical. Every hazard (`02-hazards.md`) maps to at least
one loss.

| ID | Loss |
|----|------|
| L-1 | An unauthorized or unintended privileged command executes on a fleet host. |
| L-2 | A valid host configuration is destroyed or corrupted by an erroneous reconciliation or actuation. |
| L-3 | The audit trail is silently tampered with, truncated, or incomplete, so accountability is lost. |
| L-4 | Sensitive data (credentials, keys, classified host facts, command output) is disclosed to an unauthorized party. |
| L-5 | The fleet model diverges from reality without detection (false-negative drift), so decisions rest on a stale or wrong picture. |
| L-6 | The control plane itself is taken over (a routable, unauthenticated, or SSRF-pivotable surface) and used to actuate the fleet. |

## Notes

- L-1 and L-2 are the direct-harm losses (the actuator does the wrong thing).
- L-3 and L-4 are the confidentiality/integrity losses on the evidence and data
  planes.
- L-5 is the source-of-truth loss (the model lies by omission).
- L-6 is the takeover loss (the boundary fails). It is distinct from L-1: L-1 can
  occur through a legitimate-but-misused path, L-6 is the boundary itself failing.
