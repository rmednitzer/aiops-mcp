"""RFC 6962 Merkle tree: domain separation, shape, and tamper sensitivity."""

from __future__ import annotations

import hashlib

from praxis.audit.merkle import leaf_hash, merkle_root, merkle_root_hex, node_hash


def test_empty_tree_is_sha256_of_empty() -> None:
    assert merkle_root([]) == hashlib.sha256(b"").digest()


def test_single_leaf_is_leaf_hash() -> None:
    assert merkle_root([b"a"]) == leaf_hash(b"a")


def test_two_leaves_compose() -> None:
    assert merkle_root([b"a", b"b"]) == node_hash(leaf_hash(b"a"), leaf_hash(b"b"))


def test_three_leaves_follow_rfc6962_split() -> None:
    expected = node_hash(node_hash(leaf_hash(b"a"), leaf_hash(b"b")), leaf_hash(b"c"))
    assert merkle_root([b"a", b"b", b"c"]) == expected


def test_order_matters() -> None:
    assert merkle_root([b"a", b"b"]) != merkle_root([b"b", b"a"])


def test_tamper_changes_root() -> None:
    base = merkle_root_hex([b"x", b"y", b"z"])
    assert merkle_root_hex([b"x", b"Y", b"z"]) != base


def test_leaf_and_node_domains_differ() -> None:
    # A leaf can never collide with an interior node (domain separation).
    assert leaf_hash(b"") != node_hash(b"", b"")
