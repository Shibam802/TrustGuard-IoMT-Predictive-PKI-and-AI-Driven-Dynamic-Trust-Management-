"""Simulated IoMT device: streams telemetry to the backend."""
import time, requests
import numpy as np

API = "http://127.0.0.1:8000/api"


def stream_device(device_id, n_steps=60, attack_start=None, lead_in=10, delay=0.5, seed=0, api=API):
    rng = np.random.default_rng(seed)
    for t in range(n_steps):
        x = rng.normal(0.0, 1.0, 6)
        if attack_start is not None:
            if t >= attack_start:
                x += rng.normal(6.0, 1.5, 6)
            elif t >= attack_start - lead_in:
                x += rng.normal(3.0 * (t - (attack_start - lead_in)) / lead_in, 0.6, 6)
        r = requests.post(f"{api}/telemetry", json={"device_id": device_id, "features": x.tolist()}, timeout=30).json()
        if r.get("status") == "QUARANTINED":
            break
        time.sleep(delay)
    return device_id
