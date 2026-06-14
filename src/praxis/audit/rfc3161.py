"""Timestamp stamping for Merkle roots (ADR-0008, ADR-0029).

A ``Stamper`` attests that a digest existed at a time. Verification is fail-closed:
a checkpoint with a missing or invalid token does not verify.

``LocalStamper`` (the default) is self-contained and offline: it records the digest
and a UTC time, which lets the evidence layer detect a change to the stamped root, but
its token is forgeable by anyone who can write the evidence file (it carries no
secret). ``Rfc3161Stamper`` (BL-095, ADR-0029) is the non-forgeable alternative: it
obtains an RFC 3161 timestamp token signed by an external timestamp authority, so the
token cannot be forged without the TSA's private key, and it is verifiable offline
against the TSA certificate. It is opt-in behind the ``tsa`` extra (``asn1crypto`` +
``cryptography``) and the SSRF egress filter; the execution core and the default
install stay dependency-free and offline. Until a TSA is configured, OS append-only
storage on the audit, evidence, and anchor files remains the documented required
control (SECURITY.md, ADR-0019). The ``Stamper`` interface is stable either way.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from praxis._ssrf import SSRFBlocked, resolve_and_assert_egress_allowed
from praxis.clock import utc_now_iso

# (tsa_url, der_request) -> der_response. Injectable so the request/parse/verify logic
# is testable offline; the default does an SSRF-pinned HTTPS POST.
Transport = Callable[[str, bytes], bytes]

_TSP_QUERY = "application/timestamp-query"
_TSP_REPLY = "application/timestamp-reply"
_DEFAULT_TIMEOUT_S = 10.0
_DEFAULT_MAX_BYTES = 64 * 1024
_GRANTED = frozenset({"granted", "granted_with_mods"})
# Digest algorithms accepted for the TSTInfo imprint and the signer digest.
_HASHES = frozenset({"sha256", "sha384", "sha512"})


class StampError(RuntimeError):
    """A stamp could not be obtained (network, status, nonce, or imprint failure)."""


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
    """A real RFC 3161 TSA client (BL-095, ADR-0029). Needs the ``tsa`` extra.

    ``stamp`` POSTs a DER ``TimeStampReq`` to ``tsa_url`` through the SSRF egress
    filter and stores the returned token (base64 DER). ``verify`` is fail-closed: it
    re-parses the token, requires the message imprint to equal the digest, and verifies
    the TSA signature over the ``TSTInfo`` against ``cert_pem`` (the operator-configured
    TSA signing certificate). Without ``cert_pem`` it cannot verify and returns False.
    """

    kind = "rfc3161"

    def __init__(
        self,
        tsa_url: str,
        *,
        cert_pem: bytes | None = None,
        transport: Transport | None = None,
        timeout: float = _DEFAULT_TIMEOUT_S,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> None:
        # Fail loudly if the optional dependency is absent rather than silently
        # degrading a security control to the forgeable local path.
        try:
            import asn1crypto  # noqa: F401
            import cryptography  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise RuntimeError(
                "Rfc3161Stamper requires the 'tsa' extra: pip install 'praxis[tsa]'"
            ) from exc
        self.tsa_url = tsa_url
        self._cert_pem = cert_pem
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._transport: Transport = transport or self._default_transport

    def _default_transport(self, url: str, body: bytes) -> bytes:  # pragma: no cover - network
        return _https_post(url, body, timeout=self._timeout, max_bytes=self._max_bytes)

    def stamp(self, digest_hex: str) -> dict[str, object]:
        from asn1crypto import algos, tsp

        digest = bytes.fromhex(digest_hex)
        nonce = secrets.randbits(64)
        request = tsp.TimeStampReq(
            {
                "version": 1,
                "message_imprint": tsp.MessageImprint(
                    {
                        "hash_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
                        "hashed_message": digest,
                    }
                ),
                "nonce": nonce,
                "cert_req": True,
            }
        )
        response_der = self._transport(self.tsa_url, request.dump())
        response = tsp.TimeStampResp.load(response_der)
        status = response["status"]["status"].native
        if status not in _GRANTED:
            raise StampError(f"TSA did not grant the timestamp (status={status!r})")
        token = response["time_stamp_token"]
        if token.native is None:
            raise StampError("TSA response carried no timestamp token")
        tst_info = token["content"]["encap_content_info"]["content"].parsed
        if tst_info["nonce"].native != nonce:
            raise StampError("TSA response nonce did not match the request")
        if tst_info["message_imprint"]["hashed_message"].native != digest:
            raise StampError("TSA token stamped a different digest than requested")
        gen_time = tst_info["gen_time"].native
        return {
            "tsa": self.kind,
            "digest": digest_hex,
            "token_b64": base64.b64encode(token.dump()).decode("ascii"),
            "gen_time": gen_time.isoformat(),
        }

    def verify(self, digest_hex: str, token: dict[str, object]) -> bool:
        try:
            return self._verify(digest_hex, token)
        except Exception:
            # Fail-closed: any parse, decode, or crypto error is a non-verifying token.
            return False

    def _verify(self, digest_hex: str, token: dict[str, object]) -> bool:
        from asn1crypto import cms

        if not isinstance(token, dict) or token.get("tsa") != self.kind:
            return False
        token_b64 = token.get("token_b64")
        if not isinstance(token_b64, str) or self._cert_pem is None:
            return False
        token_der = base64.b64decode(token_b64, validate=True)
        content_info = cms.ContentInfo.load(token_der)
        if content_info["content_type"].native != "signed_data":
            return False
        signed_data = content_info["content"]
        tst_info = signed_data["encap_content_info"]["content"].parsed
        if tst_info["message_imprint"]["hashed_message"].native != bytes.fromhex(digest_hex):
            return False
        return _verify_signer(signed_data, self._cert_pem)


def _verify_signer(signed_data: object, cert_pem: bytes) -> bool:
    """Verify the CMS SignerInfo signature over the TSTInfo against ``cert_pem``."""
    import hashlib

    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    hash_classes: dict[str, Callable[[], hashes.HashAlgorithm]] = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }

    cert = x509.load_pem_x509_certificate(cert_pem)
    signer_infos = signed_data["signer_infos"]  # type: ignore[index]
    if len(signer_infos) != 1:
        return False
    signer = signer_infos[0]
    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        return False
    signed_attrs = signer["signed_attrs"]
    if not signed_attrs:
        return False  # signed attributes (with the message-digest) are required

    econtent = signed_data["encap_content_info"]["content"].parsed.dump()  # type: ignore[index]
    want_digest = hashlib.new(digest_name, econtent).digest()
    message_digest: bytes | None = None
    content_type_ok = False
    for attr in signed_attrs:
        attr_type = attr["type"].native
        if attr_type == "message_digest":
            message_digest = attr["values"][0].native
        elif attr_type == "content_type":
            content_type_ok = attr["values"][0].native == "tst_info"
    if message_digest != want_digest or not content_type_ok:
        return False

    # The signature is over the DER SET OF Attribute, not the [0] IMPLICIT form.
    signed_bytes = signed_attrs.untag().dump()
    signature = signer["signature"].native
    hash_cls = hash_classes[digest_name]
    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed_bytes, padding.PKCS1v15(), hash_cls())
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed_bytes, ec.ECDSA(hash_cls()))
        else:
            return False
    except InvalidSignature:
        return False

    gen_time = signed_data["encap_content_info"]["content"].parsed["gen_time"].native  # type: ignore[index]
    return bool(cert.not_valid_before_utc <= gen_time <= cert.not_valid_after_utc)


def _https_post(
    url: str, body: bytes, *, timeout: float, max_bytes: int
) -> bytes:  # pragma: no cover - network I/O
    """SSRF-pinned HTTPS POST of a DER TimeStampReq; returns the bounded response body.

    The host is vetted and the connection pinned to a resolved-and-allowed IP via the
    egress filter (ADR-0025, BL-046), so a name that rebinds to a blocked address after
    the check cannot be reached. HTTPS only; the certificate is validated for the host.
    """
    import http.client
    import socket
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise SSRFBlocked(f"TSA URL must be https, got {parsed.scheme!r}")
    ips = resolve_and_assert_egress_allowed(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    context = ssl.create_default_context()

    class _PinnedHTTPSConnection(http.client.HTTPSConnection):
        def connect(self) -> None:
            sock = socket.create_connection((ips[0], port), timeout)
            self.sock = context.wrap_socket(sock, server_hostname=host)

    conn = _PinnedHTTPSConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            parsed.path or "/",
            body=body,
            headers={
                "Host": host,
                "Content-Type": _TSP_QUERY,
                "Accept": _TSP_REPLY,
                "Content-Length": str(len(body)),
            },
        )
        response = conn.getresponse()
        if response.status != 200:
            raise StampError(f"TSA HTTP status {response.status}")
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise StampError("TSA response exceeded the size bound")
        return data
    finally:
        conn.close()


def select_stamper(*, tsa_url: str | None, tsa_cert_path: str | None) -> Stamper:
    """Choose the stamper from config: the RFC 3161 TSA when configured, else local.

    Fail-closed on misconfiguration: if a TSA URL is set, the certificate is required
    and the ``tsa`` extra must be installed, so a deployment that asked for qualified
    time gets it or a clear startup error, never a silent downgrade to the forgeable
    local stamper.
    """
    if not tsa_url:
        return LocalStamper()
    if not tsa_cert_path:
        raise RuntimeError(
            "PRAXIS_TSA_URL is set but PRAXIS_TSA_CERT is not: the TSA signing "
            "certificate is required to verify timestamp tokens (BL-095)."
        )
    cert_pem = Path(tsa_cert_path).read_bytes()
    return Rfc3161Stamper(tsa_url, cert_pem=cert_pem)
