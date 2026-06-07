"""Timestamp stamping for Merkle roots (ADR-0008).

A ``Stamper`` attests that a digest existed at a time. Verification is fail-closed:
a checkpoint with a missing or invalid token does not verify.

``LocalStamper`` (the default) is self-contained and offline: it records the digest
and a UTC time, which lets the evidence layer detect any change to the stamped root
(the token's digest will not match a recomputed, tampered root). A real RFC 3161
TSA (qualified external time) is a ``Stamper`` implementation behind an optional
dependency and network; see LIMITATIONS. The interface is stable either way.
"""

from __future__ import annotations

from typing import Protocol

from praxis.clock import utc_now_iso


class Stamper(Protocol):
    def stamp(self, digest_hex: str) -> dict[str, object]:
        """Return a timestamp token attesting ``digest_hex`` at the current time."""
        ...

    def verify(self, digest_hex: str, token: dict[str, object]) -> bool:
        """Fail-closed: True only if the token validly attests ``digest_hex``."""
        ...


class LocalStamper:
    """Self-contained local attestation. Not qualified external time (see module doc)."""

    kind = "local"

    def stamp(self, digest_hex: str) -> dict[str, object]:
        return {"tsa": self.kind, "digest": digest_hex, "ts": utc_now_iso()}

    def verify(self, digest_hex: str, token: dict[str, object]) -> bool:
        return (
            isinstance(token, dict)
            and token.get("tsa") == self.kind
            and token.get("digest") == digest_hex
            and isinstance(token.get("ts"), str)
        )


class Rfc3161Stamper:
    """A real RFC 3161 TSA client. Requires the optional dependency and network."""

    def __init__(self, tsa_url: str) -> None:
        self.tsa_url = tsa_url

    def stamp(self, digest_hex: str) -> dict[str, object]:  # pragma: no cover - needs network/dep
        raise NotImplementedError(
            "Rfc3161Stamper requires an ASN.1/TSP backend and network access; "
            "use LocalStamper offline. See LIMITATIONS and ADR-0008."
        )

    def verify(self, digest_hex: str, token: dict[str, object]) -> bool:  # pragma: no cover
        # Fail-closed: an unimplemented backend never reports a token as valid.
        return False
