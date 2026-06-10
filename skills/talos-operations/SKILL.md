---
name: talos-operations
description: Operate a Talos Linux Kubernetes cluster with talosctl: health checks, etcd snapshot and restore, node upgrade, and kubeconfig rotation.
kind: tool
---

# Talos operations

Tool skill. Talos is API-only and immutable: every operation goes through
`talosctl` over the mTLS gRPC API, never SSH (SEC-5). Covers `talosctl health`,
`etcd` snapshot and restore, `upgrade` of a node, and kubeconfig rotation.

Destructive verbs (reset, upgrade) classify as T3 in the executor and require a
server-minted, single-use approval token (from a prior dry run) and a single
target; a real upgrade also needs a passing `talosctl health` pre-flight. Endpoints are the control-plane IPs talosctl
connects to; nodes are the machines a request is about.
