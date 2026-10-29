"""
TrustGuard-IoMT backend (FastAPI).

Receives device telemetry, scores trust, forecasts the trend, applies the
three-tier policy, acts on the CA, and records every certificate event in the
DualLedger (local SHA-256 hash chain + TrustGuardLedger smart contract).

Run:  uvicorn server.app:app --port 8000
The blockchain node is optional: if it is down the events are queued and
pushed to the chain automatically once it is reachable.
"""
import sys, threading, time, os
from pathlib import Path
from collections import deque

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "blockchain" / "python_client"))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ca.hybrid_ca import HybridCA
from trust_engine.scoring import TrustScorer
from trust_engine.forecasting import TrustTrajectoryForecaster
from policy.controller import PolicyController, Tier
from ledger.chain_bridge import DualLedger
from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS

TAU_C = float(os.getenv("TG_TAU_C", 30))        # Tier 3 threshold (current score)
TAU_F = float(os.getenv("TG_TAU_F", 28))        # Tier 2 threshold (forecast)  [tuned]
WINDOW = int(os.getenv("TG_WINDOW", 10))
HORIZON = 4
PERSIST = int(os.getenv("TG_PERSIST", 2))     # consecutive low scores needed for Tier 3
RPC_URL = os.getenv("TG_RPC_URL", "http://127.0.0.1:8545")

app = FastAPI(title="TrustGuard-IoMT")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
lock = threading.RLock()


class Telemetry(BaseModel):
    device_id: str
    features: list[float]


class State:
    def __init__(self):
        train = generate_synthetic_dataset(n_devices=8, n_steps=200, attack_devices=(), seed=11)
        self.scorer = TrustScorer(contamination=0.1).fit(train[FEATURE_COLUMNS])
        self.reset()

    def reset(self):
        self.ca = HybridCA(cert_validity_minutes=120)
        self.ledger = DualLedger(None)
        self.forecaster = TrustTrajectoryForecaster(window_size=WINDOW, horizon=HORIZON, breach_threshold=TAU_F)
        self.policy = PolicyController(self.ca, self.ledger, current_breach_threshold=TAU_C)
        self.devices = {}          # id -> dict
        self.alerts = deque(maxlen=200)
        self.last_chain_try = 0.0
        self.chain_error = None
        self.try_connect(force=True)

    def try_connect(self, force=False):
        if self.ledger.chain is not None:
            return
        if not force and time.time() - self.last_chain_try < 5:
            return
        self.last_chain_try = time.time()
        try:
            from chain_ledger import ChainLedger
            self.ledger.chain = ChainLedger(rpc_url=RPC_URL)
            self.chain_error = None
            self.ledger.flush()
        except Exception as e:           # node down / not deployed
            self.chain_error = str(e)[:160]


S = State()


def _ledger_view():
    rc = {i: (r, s) for i, r, s in S.ledger.receipts}
    out = []
    for e in S.ledger.entries:
        r = rc.get(e.index)
        out.append({
            "index": e.index, "time": e.timestamp, "event": e.event_type, "device": e.device_id,
            "cert": e.cert_id, "detail": e.detail, "hash": e.entry_hash,
            "on_chain": r is not None,
            "tx_hash": r[0]["tx_hash"] if r else None,
            "block": r[0]["block_number"] if r else None,
            "gas": r[0]["gas_used"] if r else None,
        })
    return out


@app.post("/api/telemetry")
def telemetry(t: Telemetry):
    with lock:
        S.try_connect()
        S.ledger.flush()
        dev = S.devices.get(t.device_id)
        if dev is None:
            _, pub = HybridCA.generate_device_keypair()
            cert = S.ca.issue_certificate(t.device_id, pub)
            S.ledger.append("ISSUE", t.device_id, cert.cert_id, "Initial enrollment")
            dev = S.devices[t.device_id] = {"cert": cert, "history": [], "tier": "TIER_1_NORMAL",
                                            "status": "ACTIVE", "rotations": 0}
        if dev["status"] == "QUARANTINED":
            return {"device_id": t.device_id, "status": "QUARANTINED"}
        import pandas as pd
        x = pd.DataFrame([t.features], columns=FEATURE_COLUMNS)
        score = float(S.scorer.score(x)[0])
        fc = S.forecaster.update(t.device_id, score)
        step = len(dev["history"])
        # persistence rule: Tier 3 needs PERSIST consecutive low scores (cuts one-off false alarms)
        recent = [h["score"] for h in dev["history"][-(PERSIST - 1):]] if PERSIST > 1 else []
        effective = max(recent + [score])
        if effective != score:
            import dataclasses
            fc = dataclasses.replace(fc, current_score=effective)
        dec = S.policy.evaluate(fc, dev["cert"])
        dev["history"].append({"t": step, "score": round(score, 1), "forecast": round(fc.forecasted_score, 1)})
        dev["tier"] = dec.tier.value
        if dec.tier == Tier.PREDICTIVE_ESCALATION:
            dev["cert"] = S.ca.issued_certs[dec.new_cert_id]; dev["rotations"] += 1; dev["status"] = "ROTATED"
        elif dec.tier == Tier.CONFIRMED_BREACH:
            dev["status"] = "QUARANTINED"
        if dec.tier != Tier.NORMAL:
            S.alerts.appendleft({"time": time.strftime("%H:%M:%S"), "device": t.device_id, "tier": dec.tier.value,
                                 "action": dec.action_taken, "score": round(score, 1),
                                 "forecast": round(fc.forecasted_score, 1)})
        return {"device_id": t.device_id, "score": round(score, 1), "tier": dec.tier.value, "status": dev["status"]}


@app.get("/api/devices")
def devices():
    with lock:
        out = []
        for did, d in sorted(S.devices.items()):
            h = d["history"]
            out.append({"device_id": did, "status": d["status"], "tier": d["tier"], "cert_id": d["cert"].cert_id,
                        "rotations": d["rotations"], "score": h[-1]["score"] if h else None,
                        "forecast": h[-1]["forecast"] if h else None, "history": h[-80:]})
        return out


@app.get("/api/alerts")
def alerts():
    with lock:
        return list(S.alerts)


@app.get("/api/ledger")
def ledger():
    with lock:
        S.try_connect(); S.ledger.flush()
        return _ledger_view()


@app.get("/api/status")
def status():
    with lock:
        S.try_connect()
        ch = S.ledger.chain
        n_chain = None
        try:
            n_chain = ch.entry_count() if ch else None
        except Exception:
            ch = None
        return {
            "chain_connected": ch is not None, "chain_error": S.chain_error,
            "contract": ch.address if ch else None, "rpc": RPC_URL,
            "local_entries": len(S.ledger.entries), "onchain_entries": n_chain,
            "pending": len(S.ledger.pending), "hash_chain_valid": S.ledger.verify_chain(),
            "thresholds": {"persist": PERSIST, "tau_c": TAU_C, "tau_f": TAU_F, "window": WINDOW, "horizon": HORIZON},
        }


@app.get("/api/verify")
def verify():
    """Cross-check every local entry against the smart contract."""
    with lock:
        t0 = time.perf_counter()
        ok = S.ledger.verify_against_chain() if S.ledger.chain else False
        return {"in_sync": bool(ok), "seconds": round(time.perf_counter() - t0, 2),
                "hash_chain_valid": S.ledger.verify_chain()}


@app.post("/api/reset")
def reset():
    with lock:
        S.reset()
        return {"ok": True, "note": "Local state cleared. Chain entries from earlier runs remain on-chain; "
                                    "redeploy the contract for a clean ledger."}
