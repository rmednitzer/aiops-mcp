---
name: fleet-inventory
description: The host fleet inventory: which hosts exist, each host_type (ubuntu, talos, windows, cloud), network routing, and security posture.
kind: host-knowledge
---

# Fleet inventory

Host-knowledge skill. Describes the managed fleet: each host, its `host_type`
(which gates the legal actuation path), its routing (ssh alias, talosctl
endpoints and nodes), and its security posture. The authoritative data lives in
`config/inventory.yaml` (gitignored) with the schema shown in
`config/inventory.example.yaml`.

Use this to answer "what hosts do we have", "is this host ubuntu or talos", and
"how do we reach it".
