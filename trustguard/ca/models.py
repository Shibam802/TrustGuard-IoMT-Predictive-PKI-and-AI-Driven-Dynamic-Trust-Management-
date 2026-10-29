"""
Data models for the Hybrid CA module.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import uuid


class CertStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"


@dataclass
class Certificate:
    """
    Represents a short-lived device certificate issued by the Hybrid CA.

    The device-facing certificate itself is signed classically (ECDSA,
    cheap to verify on constrained devices). The CA's own root/intermediate
    key is additionally signed with a post-quantum signature at issuance
    time -- see ca/hybrid_ca.py for details and the PQC placeholder notice.
    """
    cert_id: str
    device_id: str
    public_key_pem: bytes
    classical_signature: bytes
    pqc_root_signature: bytes  # signature over this cert by the PQC-signed root
    issued_at: datetime
    expires_at: datetime
    status: CertStatus = CertStatus.ACTIVE
    rotation_count: int = 0

    def is_expired(self, now: datetime = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return now >= self.expires_at

    def to_dict(self):
        return {
            "cert_id": self.cert_id,
            "device_id": self.device_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status.value,
            "rotation_count": self.rotation_count,
        }


def new_cert_id() -> str:
    return f"cert_{uuid.uuid4().hex[:12]}"
