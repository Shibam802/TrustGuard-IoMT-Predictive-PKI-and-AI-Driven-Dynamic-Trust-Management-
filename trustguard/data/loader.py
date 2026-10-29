"""
Dataset loading for TrustGuard-IoMT.

Two paths:
    1. load_real_dataset(path) -- loads an actual WUSTL-EHMS-2020 /
       CIC-IoMT-2024 style CSV (network flow features + a binary
       Label/Attack column). Point this at the real file once downloaded;
       this sandbox has no internet access to fetch it directly.
    2. generate_synthetic_dataset(...) -- produces data with the SAME
       shape/schema (numeric telemetry features + benign/attack windows,
       with a gradual degradation lead-in before each attack) so the rest
       of the pipeline can be built, run, and demoed end-to-end right now,
       without waiting on the real download. This is the "answer key"
       described in the Review-1 Q&A: because we control the generator, we
       know exactly when each attack begins, which lets us validate
       whether the forecaster predicted it early.

Both paths return a DataFrame with the same columns:
    ['device_id', 'timestamp', 'feat_1'...'feat_6', 'label']
    label: 0 = benign, 1 = attack
"""

import numpy as np
import pandas as pd


FEATURE_COLUMNS = [f"feat_{i}" for i in range(1, 7)]


def load_real_dataset(csv_path: str) -> pd.DataFrame:
    """
    Load a real downloaded IoMT intrusion dataset (e.g. WUSTL-EHMS-2020,
    CIC-IoMT-2024). Expects the CSV to have numeric telemetry columns and
    a label/attack column; adjust `label_col` / `id_col` to match the
    actual file's header names before running against real data.
    """
    df = pd.read_csv(csv_path)
    return df


def generate_synthetic_dataset(
    n_devices: int = 6,
    n_steps: int = 60,
    attack_devices: tuple = (1, 4),
    lead_in_steps: int = 10,
    seed: int = 7,
) -> pd.DataFrame:
    """
    Generate telemetry for `n_devices` simulated IoMT devices over
    `n_steps` time windows. Devices listed in `attack_devices` experience
    a GRADUAL behavioural drift (rising feature variance/drift) for
    `lead_in_steps` steps before a sharp attack signature kicks in --
    this is the "lead-up pattern" the trajectory forecaster is trained to
    recognise (see Review-1 Q&A on dataset construction).
    """
    rng = np.random.default_rng(seed)
    rows = []

    for device_idx in range(n_devices):
        device_id = f"device_{device_idx:02d}"
        is_attacked = device_idx in attack_devices
        attack_start = rng.integers(low=n_steps // 2, high=n_steps - 5) if is_attacked else None

        for t in range(n_steps):
            base = rng.normal(loc=0.0, scale=1.0, size=len(FEATURE_COLUMNS))

            label = 0
            if is_attacked and attack_start is not None:
                lead_in_start = attack_start - lead_in_steps
                if t >= attack_start:
                    # Full attack: large feature shift.
                    base += rng.normal(loc=6.0, scale=1.5, size=len(FEATURE_COLUMNS))
                    label = 1
                elif t >= lead_in_start:
                    # Gradual lead-in: proportionally increasing drift.
                    progress = (t - lead_in_start) / lead_in_steps
                    base += rng.normal(loc=3.0 * progress, scale=0.6, size=len(FEATURE_COLUMNS))

            row = {"device_id": device_id, "timestamp": t, "label": label}
            for col, val in zip(FEATURE_COLUMNS, base):
                row[col] = val
            rows.append(row)

    return pd.DataFrame(rows)
