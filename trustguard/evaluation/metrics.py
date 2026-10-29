"""
metrics.py -- Turns raw per-device trial results (from harness.py) into
the quantitative metrics needed for the Review 3 report: detection
latency, false-positive rate, and precision/recall/F1 on breach
detection, computed separately for the predictive system and the
reactive baseline so they can be directly compared.
"""

import pandas as pd
import numpy as np


def compute_confusion_counts(df: pd.DataFrame, system: str) -> dict:
    """
    Ground truth: is_attacked (the device actually carried an attack
    signature in this trial).
    Prediction: ever_flagged (the system raised Tier 2 or Tier 3 at any
    point during the trial).
    """
    sub = df[df["system"] == system]

    tp = int(((sub["is_attacked"]) & (sub["ever_flagged"])).sum())
    fn = int(((sub["is_attacked"]) & (~sub["ever_flagged"])).sum())
    fp = int(((~sub["is_attacked"]) & (sub["ever_flagged"])).sum())
    tn = int(((~sub["is_attacked"]) & (~sub["ever_flagged"])).sum())

    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}


def compute_classification_metrics(df: pd.DataFrame, system: str) -> dict:
    counts = compute_confusion_counts(df, system)
    tp, fn, fp, tn = counts["tp"], counts["fn"], counts["fp"], counts["tn"]

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    false_positive_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

    return {
        "system": system,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
        "accuracy": round(accuracy, 4),
        **counts,
    }


def compute_detection_latency_stats(df: pd.DataFrame, system: str) -> dict:
    """
    Only meaningful for devices that were (a) actually attacked and
    (b) correctly flagged. Positive latency = caught N steps BEFORE the
    attack's full onset (the predictive system's whole point). Negative
    or zero = caught at/after onset (expected for the reactive baseline).
    """
    sub = df[(df["system"] == system) & (df["is_attacked"]) & (df["ever_flagged"])]
    latencies = sub["detection_latency"].dropna()

    if len(latencies) == 0:
        return {"system": system, "n_detected": 0, "mean_latency": None,
                "median_latency": None, "min_latency": None, "max_latency": None}

    return {
        "system": system,
        "n_detected": int(len(latencies)),
        "mean_latency": round(float(latencies.mean()), 2),
        "median_latency": round(float(latencies.median()), 2),
        "min_latency": round(float(latencies.min()), 2),
        "max_latency": round(float(latencies.max()), 2),
    }


def summarize(df: pd.DataFrame) -> dict:
    """Full summary across both systems -- the headline numbers for Review 3."""
    summary = {}
    for system in ("predictive", "reactive"):
        summary[system] = {
            **compute_classification_metrics(df, system),
            **{f"latency_{k}": v for k, v in compute_detection_latency_stats(df, system).items() if k != "system"},
        }
    return summary
