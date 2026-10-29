"""
chain_bridge.py -- DualLedger: integrates the off-chain hash-chained
ledger (ledger/ledger.py) with the on-chain TrustGuardLedger smart
contract (blockchain/).

It exposes the SAME append(event_type, device_id, cert_id, detail)
signature as RevocationLedger, so PolicyController can use it with no code
change. Every event is (1) appended to the fast local hash chain and
(2) submitted as a real transaction to the smart contract. If the node is
unreachable the event is queued and flushed later (the control loop is
never blocked by the chain), so the CA keeps working during an outage.
"""
import sys
import time
from pathlib import Path

from ledger.ledger import RevocationLedger

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "blockchain" / "python_client"))


class DualLedger(RevocationLedger):
    def __init__(self, chain=None):
        super().__init__()
        self.chain = chain              # ChainLedger instance or None
        self.pending = []               # events not yet on chain
        self.receipts = []              # (local_index, receipt dict, seconds)

    def append(self, event_type, device_id, cert_id, detail):
        entry = super().append(event_type, device_id, cert_id, detail)
        self.pending.append(entry)
        self.flush()
        return entry

    def flush(self):
        if self.chain is None:
            return
        while self.pending:
            e = self.pending[0]
            t0 = time.perf_counter()
            try:
                rc = self.chain.record_event(e.event_type, e.device_id,
                                             e.cert_id or "-", e.detail[:200])
            except Exception:
                return                  # node down: keep queued, retry later
            self.receipts.append((e.index, rc, time.perf_counter() - t0))
            self.pending.pop(0)

    def verify_against_chain(self) -> bool:
        """Cross-check: every local entry must match the on-chain entry."""
        if self.chain is None or self.chain.entry_count() != len(self.entries):
            return False
        for e in self.entries:
            if hasattr(self.chain, "verify_entry"):      # compact contract: hash check
                if not self.chain.verify_entry(e.index, e.device_id, e.cert_id or "-", e.detail[:200]):
                    return False
                continue
            c = self.chain.get_entry(e.index)
            if (c["event_type"], c["device_id"], c["cert_id"], c["detail"]) != \
               (e.event_type, e.device_id, e.cert_id or "-", e.detail[:200]):
                return False
        return self.verify_chain()
