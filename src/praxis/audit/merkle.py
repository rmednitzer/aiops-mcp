"""Merkle tree with RFC 6962 domain separation (ADR-0008).

Leaf hash is SHA-256(0x00 || leaf) and internal node hash is SHA-256(0x01 ||
left || right), so a leaf can never be confused with an interior node. The tree
shape follows RFC 6962 (split at the largest power of two below n), so roots are
reproducible by any compliant verifier.
"""

from __future__ import annotations

import hashlib

_EMPTY = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """The RFC 6962 Merkle Tree Hash over a list of leaf byte strings."""
    n = len(leaves)
    if n == 0:
        return _EMPTY
    if n == 1:
        return leaf_hash(leaves[0])
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def merkle_root_hex(leaves: list[bytes]) -> str:
    return merkle_root(leaves).hex()
