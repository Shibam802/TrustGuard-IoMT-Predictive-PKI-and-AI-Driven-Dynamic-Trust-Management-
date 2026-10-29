"""
Lightweight tamper-evident ledger for certificate lifecycle events.

Design goal: give an auditable, tamper-evident trail (like the blockchain-
based approaches in the literature survey, papers 3 & 12) WITHOUT the
consensus overhead of a real blockchain -- appropriate for constrained
IoMT deployments. This is a genuine hash chain: each entry embeds the
SHA-256 hash of the previous entry, so any retroactive edit breaks the
chain and is detectable by `verify_chain()`.

(See blockchain/ for the on-chain smart-contract version of this same
ledger, built as the course project's blockchain module.)
"""

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone


@dataclass
class LedgerEntry:
    index: int
    timestamp: str
    event_type: str      # ISSUE | ROTATE | REVOKE | ESCALATE
    device_id: str
    cert_id: str | None
    detail: str
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "device_id": self.device_id,
            "cert_id": self.cert_id,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True).encode()
        return hashlib.sha256(blob).hexdigest()


class RevocationLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self):
        self.entries: list[LedgerEntry] = []

    def append(self, event_type: str, device_id: str, cert_id: str | None, detail: str) -> LedgerEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else self.GENESIS_HASH
        entry = LedgerEntry(
            index=len(self.entries),
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            device_id=device_id,
            cert_id=cert_id,
            detail=detail,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        """Returns True if no entry has been tampered with / reordered."""
        prev_hash = self.GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                return False
            if entry.compute_hash() != entry.entry_hash:
                return False
            prev_hash = entry.entry_hash
        return True

    def to_list(self):
        return [asdict(e) for e in self.entries]
