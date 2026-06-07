---
name: ssh-hardening
description: The expected SSH hardening baseline: PermitRootLogin no, key-only authentication, and the audited sshd configuration.
kind: host-knowledge
---

# SSH hardening baseline

Host-knowledge skill. The known-good SSH posture for Ubuntu and Windows hosts:
`PermitRootLogin no`, `PasswordAuthentication no` (key-only), a restricted cipher
and MAC set, and login auditing. Drift away from this baseline (for example
`PermitRootLogin yes`) is a critical finding and a candidate for convergence.
