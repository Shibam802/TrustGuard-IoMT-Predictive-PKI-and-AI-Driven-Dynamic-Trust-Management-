"""Tests for DualLedger (no blockchain node needed: uses a fake chain)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ledger.chain_bridge import DualLedger


class FakeChain:
    def __init__(self): self.up = True; self.log = []
    def record_event(self, t, d, c, detail):
        if not self.up: raise ConnectionError("node down")
        self.log.append((t, d, c, detail)); return {"gas_used": 1, "tx_hash": "0x0", "block_number": len(self.log), "status": "success"}
    def entry_count(self): return len(self.log)
    def get_entry(self, i):
        t, d, c, x = self.log[i]; return {"event_type": t, "device_id": d, "cert_id": c, "detail": x}


def test_events_mirrored():
    ch = FakeChain(); L = DualLedger(ch)
    L.append("ISSUE", "d1", "c1", "x"); L.append("REVOKE", "d1", "c1", "y")
    assert ch.entry_count() == 2 and not L.pending and L.verify_against_chain()


def test_outage_queues_then_flushes():
    ch = FakeChain(); L = DualLedger(ch); ch.up = False
    L.append("ISSUE", "d1", "c1", "x"); L.append("ROTATE", "d1", "c2", "y")
    assert len(L.entries) == 2 and len(L.pending) == 2 and ch.entry_count() == 0
    ch.up = True; L.flush()
    assert not L.pending and ch.entry_count() == 2 and L.verify_against_chain()


def test_tamper_detected():
    L = DualLedger(FakeChain())
    for i in range(3): L.append("ISSUE", f"d{i}", f"c{i}", "x")
    L.entries[1].detail = "tampered"
    assert not L.verify_chain()


def test_rewritten_local_history_detected_against_chain():
    """Attacker rewrites a local entry AND recomputes the hash chain."""
    ch = FakeChain(); L = DualLedger(ch)
    for i in range(5): L.append("ISSUE", f"d{i}", f"c{i}", "x")
    L.entries[2].detail = "forged"
    prev = L.GENESIS_HASH
    for e in L.entries:
        e.prev_hash = prev; e.entry_hash = e.compute_hash(); prev = e.entry_hash
    assert L.verify_chain()                 # local chain alone is fooled
    assert not L.verify_against_chain()     # the on-chain copy exposes it
