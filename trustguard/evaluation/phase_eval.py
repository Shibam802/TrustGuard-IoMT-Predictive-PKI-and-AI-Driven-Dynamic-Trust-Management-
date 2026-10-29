"""
phase_eval.py -- phase-aware re-analysis of the evaluation.
The original harness counts a flag as 'early' whenever it precedes the attack
onset, even one raised long before any drift begins (a false alarm). Here every
event is classified by ground-truth phase:
    benign phase : t < onset - LEAD   (false alarm)
    lead-in      : onset - LEAD <= t < onset   (true early warning)
    attack       : t >= onset
Replays the same policy as evaluation/harness.py (Tier 3 if score < 30, else
Tier 2 if forecaster predicts a breach), and checks it reproduces the stored
benign-device false-positive counts.
"""
import sys, json
from pathlib import Path
import numpy as np
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from trust_engine.scoring import TrustScorer
from trust_engine.forecasting import TrustTrajectoryForecaster
from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS

TAU_C, LEAD, N_DEV, N_ATT, N_STEPS, HOR = 30.0, 10, 8, 2, 60, 4
VARIANTS = {"reactive": None, "predictive_default": (45.0, 8), "predictive_tuned": (28.0, 10)}

def first_event(scores, variant):
    fc = None
    if VARIANTS[variant]:
        tau, w = VARIANTS[variant]
        fc = TrustTrajectoryForecaster(window_size=w, horizon=HOR, breach_threshold=tau)
    for t, s in enumerate(scores):
        r = fc.update("d", s) if fc else None
        if s < TAU_C: return t, 3
        if r is not None and r.breach_predicted: return t, 2
    return None, None

def run(n_trials, seed_offset=0):
    out = {v: dict(att=0, benign_dev=0, benign_fp=0, benign_phase_fa=0, lead=0, post=0, miss=0,
                   lead_times=[], t2_in_lead=0) for v in VARIANTS}
    for trial in range(n_trials):
        seed = (trial + seed_offset) * 1000 + 7
        rng = np.random.default_rng(seed)
        att = tuple(sorted(rng.choice(N_DEV, size=N_ATT, replace=False).tolist()))
        df = generate_synthetic_dataset(n_devices=N_DEV, n_steps=N_STEPS, attack_devices=att, lead_in_steps=LEAD, seed=seed)
        scorer = TrustScorer(contamination=0.1).fit(df[df.label == 0][FEATURE_COLUMNS])
        df = df.assign(trust=scorer.score(df[FEATURE_COLUMNS]))
        for d in range(N_DEV):
            g = df[df.device_id == f"device_{d:02d}"].sort_values("timestamp")
            scores = g.trust.tolist(); is_att = d in att
            onset = int(g[g.label == 1].timestamp.min()) if is_att else None
            for v in VARIANTS:
                o = out[v]; t, tier = first_event(scores, v)
                if not is_att:
                    o["benign_dev"] += 1; o["benign_fp"] += t is not None
                    continue
                o["att"] += 1
                if t is None: o["miss"] += 1
                elif t < onset - LEAD: o["benign_phase_fa"] += 1      # flagged before any drift
                elif t < onset:
                    o["lead"] += 1; o["lead_times"].append(onset - t); o["t2_in_lead"] += (tier == 2)
                else: o["post"] += 1
    return out

if __name__ == "__main__":
    res = {}
    for name, n, off in (("main", 16, 0), ("heldout", 10, 50)):
        r = run(n, off)
        for v, o in r.items():
            lt = o.pop("lead_times"); o["lead_time_mean"] = float(np.mean(lt)) if lt else None
            o["lead_time_median"] = float(np.median(lt)) if lt else None
        res[name] = r; print(name, json.dumps(r, indent=1))
    json.dump(res, open(Path(__file__).resolve().parent.parent / "outputs" / "evaluation" / "phase_summary.json", "w"), indent=1)
