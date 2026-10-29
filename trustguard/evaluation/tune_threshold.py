"""
tune_threshold.py -- Sweeps forecaster parameters to find a less
trigger-happy predictive configuration than the Review-1/2 default,
without needing to retrain the IsolationForest for every config (the
scorer doesn't depend on breach_threshold/window_size, so it's computed
once per trial and reused).
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import time
import numpy as np
import pandas as pd

from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS
from trust_engine.scoring import TrustScorer
import evaluation.harness as H
from evaluation.metrics import compute_classification_metrics, compute_detection_latency_stats

N_TRIALS = 6
N_DEVICES = 8
N_ATTACKED = 2
N_STEPS = 60

CONFIGS = [
    dict(breach_threshold=45.0, window_size=8, label="default (45, w=8)"),
    dict(breach_threshold=35.0, window_size=8, label="lower threshold (35, w=8)"),
    dict(breach_threshold=30.0, window_size=8, label="lower threshold (30, w=8)"),
    dict(breach_threshold=35.0, window_size=12, label="lower + wider window (35, w=12)"),
]

print(f"Precomputing {N_TRIALS} trial scenarios + scorers (shared across configs)...")
t0 = time.time()
precomputed = []
for i in range(N_TRIALS):
    seed = i * 1000 + 7
    rng = np.random.default_rng(seed)
    attacked_devices = tuple(sorted(rng.choice(N_DEVICES, size=N_ATTACKED, replace=False).tolist()))
    df = generate_synthetic_dataset(n_devices=N_DEVICES, n_steps=N_STEPS,
                                     attack_devices=attacked_devices, lead_in_steps=10, seed=seed)
    attack_onset = {}
    for di in attacked_devices:
        dev = f"device_{di:02d}"
        rows = df[(df["device_id"] == dev) & (df["label"] == 1)]
        attack_onset[dev] = int(rows["timestamp"].min()) if len(rows) else None

    benign_df = df[df["label"] == 0]
    scorer = TrustScorer(contamination=0.1).fit(benign_df[FEATURE_COLUMNS])

    precomputed.append(dict(trial_id=i, df=df, attacked_devices=attacked_devices,
                             attack_onset=attack_onset, scorer=scorer))
print(f"Done in {time.time()-t0:.1f}s\n")

for cfg in CONFIGS:
    t0 = time.time()
    results = []
    for p in precomputed:
        for system in ("predictive", "reactive"):
            first_flag = H._run_system(
                p["df"], p["scorer"], system,
                breach_threshold=cfg["breach_threshold"], window_size=cfg["window_size"],
            )
            for di in range(N_DEVICES):
                dev = f"device_{di:02d}"
                is_attacked = di in p["attacked_devices"]
                onset = p["attack_onset"].get(dev)
                flagged = dev in first_flag
                flag_step, flag_tier = first_flag.get(dev, (None, None))
                latency = (onset - flag_step) if (flagged and is_attacked and onset is not None) else None
                results.append(dict(
                    trial_id=p["trial_id"], device_id=dev, system=system,
                    is_attacked=is_attacked, attack_onset=onset, ever_flagged=flagged,
                    first_flag_step=flag_step, first_flag_tier=flag_tier, detection_latency=latency,
                ))

    rdf = pd.DataFrame(results)
    pred_m = compute_classification_metrics(rdf, "predictive")
    pred_l = compute_detection_latency_stats(rdf, "predictive")
    print(f"{cfg['label']:38s} FPR={pred_m['false_positive_rate']:.3f}  "
          f"Recall={pred_m['recall']:.3f}  F1={pred_m['f1_score']:.3f}  "
          f"MeanLatency={pred_l['mean_latency']}  ({time.time()-t0:.1f}s)")
