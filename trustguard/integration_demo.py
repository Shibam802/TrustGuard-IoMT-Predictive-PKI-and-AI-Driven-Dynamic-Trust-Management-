"""
integration_demo.py -- End-to-end integration: synthetic IoMT telemetry ->
IsolationForest trust score -> trajectory forecast -> tiered policy ->
CA actions -> DualLedger -> smart contract. Prints evidence for DA-8.
Requires `npx hardhat node` running and the contract deployed.
"""
import sys, json, time
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).parent))
from ca.hybrid_ca import HybridCA
from trust_engine.scoring import TrustScorer
from trust_engine.forecasting import TrustTrajectoryForecaster
from policy.controller import PolicyController, Tier
from ledger.chain_bridge import DualLedger
from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS
from chain_ledger import ChainLedger, ChainLedgerCompact

N_DEV, N_STEPS, ATTACKED = 6, 50, (1, 4)
df = generate_synthetic_dataset(n_devices=N_DEV, n_steps=N_STEPS, attack_devices=ATTACKED,
                                lead_in_steps=10, seed=7)
# same protocol as evaluation/harness.py: fit on the benign rows (label 0)
scorer = TrustScorer(contamination=0.1).fit(df[df.label == 0][FEATURE_COLUMNS])

chain = ChainLedgerCompact() if "--compact" in sys.argv else ChainLedger()
base = chain.entry_count()
ledger = DualLedger(chain)
ca = HybridCA(cert_validity_minutes=120)
fc = TrustTrajectoryForecaster(window_size=8, horizon=4, breach_threshold=45.0)
pc = PolicyController(ca, ledger, current_breach_threshold=30.0)

certs = {}
for d in sorted(df.device_id.unique()):
    _, pub = HybridCA.generate_device_keypair()
    certs[d] = ca.issue_certificate(d, pub)
    ledger.append("ISSUE", d, certs[d].cert_id, "Initial enrollment")

tiers = {"TIER_1_NORMAL": 0, "TIER_2_PREDICTIVE_ESCALATION": 0, "TIER_3_CONFIRMED_BREACH": 0}
for t in sorted(df.timestamp.unique()):
    step = df[df.timestamp == t].set_index("device_id")
    for d in list(certs):
        if d not in step.index or certs[d].status.value == "REVOKED":
            continue
        s = float(scorer.score(step.loc[[d], FEATURE_COLUMNS])[0])
        dec = pc.evaluate(fc.update(d, s), certs[d])
        tiers[dec.tier.value] += 1
        if dec.new_cert_id:
            certs[d] = ca.issued_certs[dec.new_cert_id]

lat = [r[2] for r in ledger.receipts]
gas = [r[1]["gas_used"] for r in ledger.receipts]
by_type = {}
for e in ledger.entries:
    by_type.setdefault(e.event_type, []).append(ledger.receipts[e.index][1]["gas_used"])
print("devices:", N_DEV, "attacked:", ATTACKED, "steps:", N_STEPS)
print("tier decisions:", tiers)
print("local entries:", len(ledger.entries), "| on-chain new:", chain.entry_count() - base)
print("pending queue:", len(ledger.pending))
print("tx latency ms mean/max: %.1f / %.1f" % (1000*np.mean(lat), 1000*np.max(lat)))
for k, v in by_type.items():
    print("gas", k, "n=%d mean=%d" % (len(v), np.mean(v)))
print("local hash chain valid:", ledger.verify_chain())
print("local == on-chain:", ledger.verify_against_chain() if base == 0 else "n/a (chain not empty)")
print("contract:", type(chain).__name__)
print("quarantined:", sorted(pc.quarantined_devices))
# tamper test
ledger.entries[2].detail = "TAMPERED"
print("after tampering local entry 2 -> hash chain valid:", ledger.verify_chain())
json.dump({"tiers": tiers, "gas": by_type, "lat_ms": [1000*x for x in lat],
           "n_events": len(ledger.entries)}, open("integration_result.json", "w"))
