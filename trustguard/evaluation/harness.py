"""
harness.py -- Runs controlled trials comparing TrustGuard-IoMT's predictive
system against a reactive-only baseline, on identical synthetic attack
scenarios, so the two can be compared fairly.

The "reactive baseline" is the SAME system (same CA, same TrustScorer)
with the forecaster's Tier 2 (predictive escalation) disabled -- i.e. it
only acts on Tier 3 (current score already below threshold), matching how
papers 1, 2, 3, and 6 in the literature survey operate: react only after
the fact.

Each trial:
    1. Generates a fresh synthetic scenario (random seed) with a known
       set of attacked devices and a known attack onset time per device
       (the ground truth).
    2. Runs the SAME scenario through both systems.
    3. Records, per device: whether it was ever flagged, at what time
       step, and what tier.

The output is a list of per-device trial records that evaluation/metrics.py
turns into detection-latency, false-positive-rate, and precision/recall/F1
numbers.
"""

from dataclasses import dataclass, asdict

import numpy as np
import pandas as pd

from ca.hybrid_ca import HybridCA
from trust_engine.scoring import TrustScorer
from trust_engine.forecasting import TrustTrajectoryForecaster
from policy.controller import PolicyController, Tier
from ledger.ledger import RevocationLedger
from data.loader import generate_synthetic_dataset, FEATURE_COLUMNS


@dataclass
class DeviceTrialResult:
    trial_id: int
    device_id: str
    system: str              # "predictive" | "reactive"
    is_attacked: bool
    attack_onset: int | None  # ground-truth step the full attack begins, or None
    ever_flagged: bool        # did the system ever take Tier 2 or Tier 3 action
    first_flag_step: int | None
    first_flag_tier: str | None
    detection_latency: float | None
    # Positive = flagged BEFORE attack onset (early/predictive catch).
    # Negative = flagged AFTER attack onset (late/reactive catch).
    # None if never flagged, or not an attacked device.


class _NullForecaster:
    """
    Stand-in forecaster used for the reactive baseline: always reports
    no predicted breach, so the policy controller can only ever act on
    Tier 3 (current score), never Tier 2. This isolates exactly the
    effect of the forecasting component -- everything else (CA, scorer,
    thresholds) is identical between the two systems.
    """
    def __init__(self, breach_threshold):
        self.breach_threshold = breach_threshold

    def update(self, device_id, score):
        from trust_engine.forecasting import ForecastResult
        return ForecastResult(
            device_id=device_id,
            current_score=score,
            trend_slope=0.0,
            forecasted_score=score,
            breach_predicted=False,   # <-- Tier 2 can never fire
            steps_to_breach=None,
        )


def _run_system(df: pd.DataFrame, scorer: TrustScorer, system: str,
                 breach_threshold: float = 45.0, current_threshold: float = 30.0,
                 window_size: int = 8, horizon: int = 4):
    """Runs one scenario through either the predictive or reactive system."""
    ca = HybridCA(cert_validity_minutes=120)
    ledger = RevocationLedger()

    if system == "predictive":
        forecaster = TrustTrajectoryForecaster(
            window_size=window_size, horizon=horizon, breach_threshold=breach_threshold
        )
    elif system == "reactive":
        forecaster = _NullForecaster(breach_threshold=breach_threshold)
    else:
        raise ValueError(system)

    controller = PolicyController(ca, ledger, current_breach_threshold=current_threshold)

    active_certs = {}
    first_flag = {}  # device_id -> (step, tier)
    for device_id in sorted(df["device_id"].unique()):
        _, pub_pem = HybridCA.generate_device_keypair()
        cert = ca.issue_certificate(device_id, pub_pem)
        active_certs[device_id] = cert

    for t in sorted(df["timestamp"].unique()):
        step_df = df[df["timestamp"] == t].set_index("device_id")
        for device_id in active_certs:
            if device_id not in step_df.index:
                continue
            cert = active_certs[device_id]
            if cert.status.value == "REVOKED":
                continue

            features = step_df.loc[[device_id], FEATURE_COLUMNS]
            trust_score = float(scorer.score(features)[0])
            forecast = forecaster.update(device_id, trust_score)

            decision = controller.evaluate(forecast, cert)
            if decision.tier != Tier.NORMAL and device_id not in first_flag:
                first_flag[device_id] = (t, decision.tier.value)
            if decision.new_cert_id:
                active_certs[device_id] = ca.issued_certs[decision.new_cert_id]

    return first_flag


def run_trial(trial_id: int, n_devices: int = 8, n_attacked: int = 2,
              n_steps: int = 60, lead_in_steps: int = 10, seed: int = None) -> list:
    """Runs ONE scenario through BOTH systems and returns per-device results."""
    seed = seed if seed is not None else trial_id * 1000 + 7
    rng = np.random.default_rng(seed)
    attacked_devices = tuple(sorted(rng.choice(n_devices, size=n_attacked, replace=False).tolist()))

    df = generate_synthetic_dataset(
        n_devices=n_devices, n_steps=n_steps,
        attack_devices=attacked_devices, lead_in_steps=lead_in_steps, seed=seed,
    )

    # Ground truth: for each attacked device, the first timestamp labeled
    # as a full attack (label == 1).
    attack_onset = {}
    for device_idx in attacked_devices:
        device_id = f"device_{device_idx:02d}"
        attack_rows = df[(df["device_id"] == device_id) & (df["label"] == 1)]
        attack_onset[device_id] = int(attack_rows["timestamp"].min()) if len(attack_rows) else None

    # Fit ONE scorer per trial, shared by both systems, trained on this
    # trial's benign rows -- so any difference in results is purely due
    # to the forecaster, not a different model.
    benign_df = df[df["label"] == 0]
    scorer = TrustScorer(contamination=0.1).fit(benign_df[FEATURE_COLUMNS])

    results = []
    for system in ("predictive", "reactive"):
        first_flag = _run_system(df, scorer, system)

        for device_idx in range(n_devices):
            device_id = f"device_{device_idx:02d}"
            is_attacked = device_idx in attacked_devices
            onset = attack_onset.get(device_id)

            flagged = device_id in first_flag
            flag_step, flag_tier = first_flag.get(device_id, (None, None))

            latency = None
            if flagged and is_attacked and onset is not None:
                # Positive = caught BEFORE attack onset (early).
                latency = onset - flag_step

            results.append(DeviceTrialResult(
                trial_id=trial_id, device_id=device_id, system=system,
                is_attacked=is_attacked, attack_onset=onset,
                ever_flagged=flagged, first_flag_step=flag_step,
                first_flag_tier=flag_tier, detection_latency=latency,
            ))

    return results


def run_many_trials(n_trials: int = 20, **trial_kwargs) -> pd.DataFrame:
    all_results = []
    for i in range(n_trials):
        all_results.extend(run_trial(trial_id=i, **trial_kwargs))
    return pd.DataFrame([asdict(r) for r in all_results])
