"""RFC 3161 stamper (BL-095, ADR-0029): offline build/parse/verify and fail-closed.

No live TSA: the suite generates a self-signed TSA certificate and signs RFC 3161
tokens itself (the inverse of ``verify``), then drives ``Rfc3161Stamper`` through an
injected transport. The SSRF-pinned HTTPS transport is covered by the egress filter's
own tests (BL-046); here the transport is faked.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest

from praxis._ssrf import SSRFBlocked
from praxis.audit.rfc3161 import LocalStamper, Rfc3161Stamper, StampError, select_stamper

asn1_tsp = pytest.importorskip("asn1crypto.tsp")
asn1_cms = pytest.importorskip("asn1crypto.cms")
asn1_algos = pytest.importorskip("asn1crypto.algos")
asn1_x509 = pytest.importorskip("asn1crypto.x509")
crypto_x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

_NOW = datetime.datetime(2026, 6, 14, 12, 0, 0, tzinfo=datetime.UTC)


def _tsa_keypair() -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """Return (key, cert_der, cert_pem) for a self-signed test TSA."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, "test-tsa")])
    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(_NOW - datetime.timedelta(days=1))
        .not_valid_after(_NOW + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return (
        key,
        cert.public_bytes(serialization.Encoding.DER),
        cert.public_bytes(serialization.Encoding.PEM),
    )


def _make_token(
    digest: bytes,
    *,
    key: rsa.RSAPrivateKey,
    cert_der: bytes,
    nonce: int,
    gen_time: datetime.datetime = _NOW,
) -> object:
    """Build a signed RFC 3161 token (cms.ContentInfo) over ``digest``."""
    tst_info = asn1_tsp.TSTInfo(
        {
            "version": 1,
            "policy": "1.2.3.4",
            "message_imprint": asn1_tsp.MessageImprint(
                {
                    "hash_algorithm": asn1_algos.DigestAlgorithm({"algorithm": "sha256"}),
                    "hashed_message": digest,
                }
            ),
            "serial_number": 42,
            "gen_time": gen_time,
            "nonce": nonce,
        }
    )
    econtent = tst_info.dump()
    signed_attrs = asn1_cms.CMSAttributes(
        [
            asn1_cms.CMSAttribute(
                {"type": "content_type", "values": [asn1_cms.ContentType("tst_info")]}
            ),
            asn1_cms.CMSAttribute(
                {
                    "type": "message_digest",
                    "values": [asn1_cms.OctetString(hashlib.sha256(econtent).digest())],
                }
            ),
        ]
    )
    signature = key.sign(signed_attrs.dump(), padding.PKCS1v15(), hashes.SHA256())
    signer_info = asn1_cms.SignerInfo(
        {
            "version": 1,
            "sid": asn1_cms.SignerIdentifier(
                {
                    "issuer_and_serial_number": asn1_cms.IssuerAndSerialNumber(
                        {"issuer": asn1_x509.Certificate.load(cert_der).issuer, "serial_number": 7}
                    )
                }
            ),
            "digest_algorithm": asn1_algos.DigestAlgorithm({"algorithm": "sha256"}),
            "signed_attrs": signed_attrs,
            "signature_algorithm": asn1_algos.SignedDigestAlgorithm(
                {"algorithm": "rsassa_pkcs1v15"}
            ),
            "signature": signature,
        }
    )
    signed_data = asn1_cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [asn1_algos.DigestAlgorithm({"algorithm": "sha256"})],
            "encap_content_info": asn1_cms.EncapsulatedContentInfo(
                {"content_type": "tst_info", "content": tst_info}
            ),
            "certificates": [asn1_x509.Certificate.load(cert_der)],
            "signer_infos": [signer_info],
        }
    )
    return asn1_cms.ContentInfo({"content_type": "signed_data", "content": signed_data})


def _response(token: object, *, status: str = "granted") -> bytes:
    resp = asn1_tsp.TimeStampResp({"status": {"status": status}, "time_stamp_token": token})
    return bytes(resp.dump())


def _granting_transport(
    key: rsa.RSAPrivateKey, cert_der: bytes, *, status: str = "granted"
) -> Callable[[str, bytes], bytes]:
    """A transport that parses the request and returns a matching signed token."""

    def transport(_url: str, request_der: bytes) -> bytes:
        request = asn1_tsp.TimeStampReq.load(request_der)
        nonce = request["nonce"].native
        digest = request["message_imprint"]["hashed_message"].native
        token = _make_token(digest, key=key, cert_der=cert_der, nonce=nonce)
        return _response(token, status=status)

    return transport


def test_stamp_then_verify_round_trips() -> None:
    key, cert_der, cert_pem = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=cert_pem, transport=_granting_transport(key, cert_der)
    )
    root = hashlib.sha256(b"merkle-root").hexdigest()
    token = stamper.stamp(root)
    assert token["tsa"] == "rfc3161"
    assert token["digest"] == root
    assert isinstance(token["token_b64"], str)
    assert stamper.verify(root, token) is True


def test_verify_rejects_a_different_digest() -> None:
    key, cert_der, cert_pem = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=cert_pem, transport=_granting_transport(key, cert_der)
    )
    token = stamper.stamp(hashlib.sha256(b"root-a").hexdigest())
    assert stamper.verify(hashlib.sha256(b"root-b").hexdigest(), token) is False


def test_verify_rejects_a_tampered_token() -> None:
    key, cert_der, cert_pem = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=cert_pem, transport=_granting_transport(key, cert_der)
    )
    root = hashlib.sha256(b"root").hexdigest()
    token = stamper.stamp(root)
    raw = bytearray(base64.b64decode(token["token_b64"]))  # type: ignore[arg-type]
    raw[-1] ^= 0xFF  # flip a byte in the signature region
    token["token_b64"] = base64.b64encode(bytes(raw)).decode("ascii")
    assert stamper.verify(root, token) is False


def test_verify_rejects_a_foreign_signer() -> None:
    key_a, cert_der_a, _ = _tsa_keypair()
    _, _, cert_pem_b = _tsa_keypair()  # a different TSA's certificate
    # The token is signed by TSA A, but the stamper is configured with TSA B's cert.
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr",
        cert_pem=cert_pem_b,
        transport=_granting_transport(key_a, cert_der_a),
    )
    root = hashlib.sha256(b"root").hexdigest()
    token = stamper.stamp(root)
    assert stamper.verify(root, token) is False


def test_verify_without_cert_is_fail_closed() -> None:
    key, cert_der, _ = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=None, transport=_granting_transport(key, cert_der)
    )
    token = stamper.stamp(hashlib.sha256(b"root").hexdigest())
    assert stamper.verify(token["digest"], token) is False  # type: ignore[arg-type]


def test_verify_rejects_malformed_tokens() -> None:
    _, _, cert_pem = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=cert_pem, transport=lambda _u, _b: b""
    )
    digest = hashlib.sha256(b"root").hexdigest()
    junk_b64 = base64.b64encode(b"junk").decode("ascii")
    assert stamper.verify(digest, {"tsa": "local", "digest": digest, "ts": "x"}) is False
    assert stamper.verify(digest, {"tsa": "rfc3161"}) is False
    assert stamper.verify(digest, {"tsa": "rfc3161", "token_b64": "not base64!!"}) is False
    assert stamper.verify(digest, {"tsa": "rfc3161", "token_b64": junk_b64}) is False


def test_stamp_raises_on_rejection() -> None:
    key, cert_der, cert_pem = _tsa_keypair()
    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr",
        cert_pem=cert_pem,
        transport=_granting_transport(key, cert_der, status="rejection"),
    )
    with pytest.raises(StampError):
        stamper.stamp(hashlib.sha256(b"root").hexdigest())


def test_stamp_raises_on_imprint_mismatch() -> None:
    key, cert_der, cert_pem = _tsa_keypair()

    def wrong_digest_transport(_url: str, _req: bytes) -> bytes:
        # Ignore the request and stamp an unrelated digest with an unrelated nonce.
        token = _make_token(hashlib.sha256(b"other").digest(), key=key, cert_der=cert_der, nonce=1)
        return _response(token)

    stamper = Rfc3161Stamper(
        "https://tsa.example/tsr", cert_pem=cert_pem, transport=wrong_digest_transport
    )
    with pytest.raises(StampError):
        stamper.stamp(hashlib.sha256(b"root").hexdigest())


def test_select_stamper_defaults_to_local() -> None:
    assert isinstance(select_stamper(tsa_url=None, tsa_cert_path=None), LocalStamper)
    assert isinstance(select_stamper(tsa_url="", tsa_cert_path="/x"), LocalStamper)


def test_select_stamper_requires_cert_when_url_set() -> None:
    with pytest.raises(RuntimeError, match="PRAXIS_TSA_CERT"):
        select_stamper(tsa_url="https://tsa.example/tsr", tsa_cert_path=None)


def test_select_stamper_builds_rfc3161_with_cert(tmp_path: Path) -> None:
    _, _, cert_pem = _tsa_keypair()
    cert_file = tmp_path / "tsa.pem"
    cert_file.write_bytes(cert_pem)
    stamper = select_stamper(tsa_url="https://tsa.example/tsr", tsa_cert_path=str(cert_file))
    assert isinstance(stamper, Rfc3161Stamper)


def test_select_stamper_fails_closed_on_unreadable_cert(tmp_path: Path) -> None:
    missing = tmp_path / "absent" / "tsa.pem"  # parent does not exist either
    with pytest.raises(RuntimeError, match="PRAXIS_TSA_CERT"):
        select_stamper(tsa_url="https://tsa.example/tsr", tsa_cert_path=str(missing))


def test_default_transport_routes_through_the_ssrf_egress_filter() -> None:
    # BL-046 (wiring half): the default, non-injected transport vets the TSA address
    # through the rebinding-aware egress filter and pins to it, so a private-range URL
    # is refused before any socket. This proves the stamper is the filter's first live
    # egress consumer, exercised offline with no real network.
    stamper = Rfc3161Stamper("https://10.0.0.1/tsr")  # default transport; no cert needed to stamp
    with pytest.raises(SSRFBlocked):
        stamper.stamp(hashlib.sha256(b"root").hexdigest())
