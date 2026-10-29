"""
run_evaluation.py -- THE authoritative Review 3 evaluation run.

Compares three variants over N_TRIALS identical synthetic scenarios:
    - reactive            : forecaster disabled (Tier 2 never fires),
                             matching papers 1/2/3/6's reactive-only approach
    - predictive_default  : the Review 1/2 default forecaster config
                             (breach_threshold=45, window_size=8)
    - predictive_tuned     : threshold swept down to reduce false positives
                             (breach_threshold=28, window_size=10), found via
                             evaluation/tune_threshold.py

Writes outputs/evaluation/full_results.csv (raw per-device records) and
outputs/evaluation/summary.json (the headline metrics table).
"""

import sys
import json
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pandas as pd

from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS
from trust_engine.scoring import TrustScorer
import evaluation.harness as H
from evaluation.metrics import compute_classification_metrics, compute_detection_latency_stats

N_TRIALS = 16
N_DEVICES = 8
N_ATTACKED = 2
N_STEPS = 60

ALL_VARIANTS = {
    "reactive": dict(system="reactive", breach_threshold=45.0, window_size=8),
    "predictive_default": dict(system="predictive", breach_threshold=45.0, window_size=8),
    "predictive_tuned": dict(system="predictive", breach_threshold=28.0, window_size=10),
}

# Run just ONE variant per invocation (pass its name as argv[1]) to stay
# comfortably under the sandbox's per-command time limit; results from
# each run are appended to the same CSV and combined afterward.
only_variant = sys.argv[1] if len(sys.argv) > 1 else None
VARIANTS = {only_variant: ALL_VARIANTS[only_variant]} if only_variant else ALL_VARIANTS

OUT_DIR = Path(__file__).parent.parent / "outputs" / "evaluation"
OUT_DIR.mkdir(parents=True, exist_ok=True)

print(f"Precomputing {N_TRIALS} trial scenarios + scorers...")
t_start = time.time()
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
print(f"  done in {time.time()-t_start:.1f}s")

all_results = []
for variant_name, params in VARIANTS.items():
    t0 = time.time()
    for p in precomputed:
        first_flag = H._run_system(
            p["df"], p["scorer"], params["system"],
            breach_threshold=params["breach_threshold"], window_size=params["window_size"],
        )
        for di in range(N_DEVICES):
            dev = f"device_{di:02d}"
            is_attacked = di in p["attacked_devices"]
            onset = p["attack_onset"].get(dev)
            flagged = dev in first_flag
            flag_step, flag_tier = first_flag.get(dev, (None, None))
            latency = (onset - flag_step) if (flagged and is_attacked and onset is not None) else None
            all_results.append(dict(
                trial_id=p["trial_id"], device_id=dev, variant=variant_name,
                is_attacked=is_attacked, attack_onset=onset, ever_flagged=flagged,
                first_flag_step=flag_step, first_flag_tier=flag_tier, detection_latency=latency,
            ))
    print(f"  {variant_name}: {time.time()-t0:.1f}s")

df_new = pd.DataFrame(all_results)

# Append to (rather than overwrite) full_results.csv, since this script
# may be invoked once per variant across separate commands.
results_path = OUT_DIR / "full_results.csv"
if results_path.exists() and only_variant:
    existing = pd.read_csv(results_path)
    existing = existing[existing["variant"] != only_variant]  # replace this variant's rows if rerun
    df_all = pd.concat([existing, df_new], ignore_index=True)
else:
    df_all = df_new

df_all.to_csv(results_path, index=False)
print(f"\nWrote {results_path} ({len(df_all)} total rows, {len(df_new)} new)")

# Only compute/print the full summary once all three variants are present.
variants_present = set(df_all["variant"].unique())
if variants_present == set(ALL_VARIANTS.keys()):
    summary = {}
    for variant_name in ALL_VARIANTS:
        sub = df_all[df_all["variant"] == variant_name].rename(columns={"variant": "system"})
        sub = sub.assign(system=variant_name)
        cls = compute_classification_metrics(sub, variant_name)
        lat = compute_detection_latency_stats(sub, variant_name)
        summary[variant_name] = {**cls, **{f"latency_{k}": v for k, v in lat.items() if k != "system"}}

    with open(OUT_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)

    print(f"Wrote {OUT_DIR / 'summary.json'}\n")
    print(json.dumps(summary, indent=2, default=str))
else:
    print(f"Variants collected so far: {variants_present}. "
          f"Still need: {set(ALL_VARIANTS.keys()) - variants_present}")

print(f"\nThis run's time: {time.time()-t_start:.1f}s")
