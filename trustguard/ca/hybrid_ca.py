"""
Hybrid Certificate Authority for TrustGuard-IoMT.

Design:
    - Device-facing certificates use REAL classical ECDSA (P-256) signatures
      via the `cryptography` library. This is cheap enough for constrained
      bedside devices to verify on every message.
    - The CA's root key additionally produces a post-quantum signature over
      every issued certificate, so the root of trust itself is protected
      against "harvest-now-decrypt-later" attacks even though the
      day-to-day device certificate stays classical-only.

IMPORTANT / HONEST LIMITATION:
    Real PQC signing (CRYSTALS-Dilithium, per NIST FIPS 204) requires the
    `liboqs` C library, which needs `cmake` + a C toolchain to build from
    source. That toolchain is not available in this development sandbox,
    so `_pqc_sign_placeholder()` below is a SIMULATED stand-in: it produces
    a deterministic, correctly-shaped signature using SHA3-512 + a secret
    root seed, NOT a real lattice-based PQC signature. It preserves the
    system's architecture and API (drop-in replaceable) but provides NO
    real post-quantum security guarantee yet.

    To make this production-real: replace `_pqc_sign_placeholder` /
    `_pqc_verify_placeholder` with `oqs.Signature("Dilithium3")` calls from
    the `liboqs-python` package (works outside this sandbox once `cmake`
    and a C compiler are available to build liboqs).
"""

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

from .models import Certificate, CertStatus, new_cert_id


class HybridCA:
    def __init__(self, cert_validity_minutes: int = 60):
        # Real classical root keypair (ECDSA P-256) -- this is what actually
        # signs every device certificate day-to-day.
        self._root_private_key = ec.generate_private_key(ec.SECP256R1())
        self.root_public_key = self._root_private_key.public_key()

        # Simulated PQC root seed (see module docstring). In a real
        # deployment this is replaced by an actual Dilithium keypair.
        self._pqc_root_seed = os.urandom(32)

        self.cert_validity = timedelta(minutes=cert_validity_minutes)
        self.issued_certs: dict[str, Certificate] = {}

    # ---------- classical signing (real) ----------
    def _classical_sign(self, payload: bytes) -> bytes:
        return self._root_private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def _classical_verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self.root_public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    # ---------- PQC signing (SIMULATED PLACEHOLDER -- see docstring) ----------
    def _pqc_sign_placeholder(self, payload: bytes) -> bytes:
        """Deterministic HMAC-SHA3-512 stand-in shaped like a PQC signature."""
        return hmac.new(self._pqc_root_seed, payload, hashlib.sha3_512).digest()

    def _pqc_verify_placeholder(self, payload: bytes, signature: bytes) -> bool:
        expected = self._pqc_sign_placeholder(payload)
        return hmac.compare_digest(expected, signature)

    # ---------- device keypair helper (simulates device-side keygen) ----------
    @staticmethod
    def generate_device_keypair():
        priv = ec.generate_private_key(ec.SECP256R1())
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return priv, pub_pem

    # ---------- issuance / rotation / revocation ----------
    def issue_certificate(self, device_id: str, device_public_key_pem: bytes) -> Certificate:
        now = datetime.now(timezone.utc)
        cert_id = new_cert_id()
        expires_at = now + self.cert_validity

        payload = self._build_payload(cert_id, device_id, device_public_key_pem, now, expires_at)
        classical_sig = self._classical_sign(payload)
        pqc_sig = self._pqc_sign_placeholder(payload)

        cert = Certificate(
            cert_id=cert_id,
            device_id=device_id,
            public_key_pem=device_public_key_pem,
            classical_signature=classical_sig,
            pqc_root_signature=pqc_sig,
            issued_at=now,
            expires_at=expires_at,
        )
        self.issued_certs[cert_id] = cert
        return cert

    def rotate_certificate(self, old_cert: Certificate, reason: str = "scheduled") -> Certificate:
        """Issue a fresh certificate for the same device and mark the old one ROTATED."""
        old_cert.status = CertStatus.ROTATED
        new_cert = self.issue_certificate(old_cert.device_id, old_cert.public_key_pem)
        new_cert.rotation_count = old_cert.rotation_count + 1
        return new_cert

    def revoke_certificate(self, cert: Certificate, reason: str = "trust_breach"):
        cert.status = CertStatus.REVOKED
        return cert

    def verify_certificate(self, cert: Certificate) -> bool:
        payload = self._build_payload(
            cert.cert_id, cert.device_id, cert.public_key_pem, cert.issued_at, cert.expires_at
        )
        classical_ok = self._classical_verify(payload, cert.classical_signature)
        pqc_ok = self._pqc_verify_placeholder(payload, cert.pqc_root_signature)
        not_expired = not cert.is_expired()
        not_revoked = cert.status != CertStatus.REVOKED
        return classical_ok and pqc_ok and not_expired and not_revoked

    @staticmethod
    def _build_payload(cert_id, device_id, pub_key_pem, issued_at, expires_at) -> bytes:
        return (
            f"{cert_id}|{device_id}|{issued_at.isoformat()}|{expires_at.isoformat()}"
        ).encode() + pub_key_pem
