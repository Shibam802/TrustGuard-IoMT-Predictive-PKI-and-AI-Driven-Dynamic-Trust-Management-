"""
make_charts.py -- Generates the Review 3 evaluation figures from the real
run_evaluation.py output (outputs/evaluation/full_results.csv + summary.json).
"""

import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

OUT_DIR = Path(__file__).parent.parent / "outputs" / "evaluation"

with open(OUT_DIR / "summary.json") as f:
    summary = json.load(f)
df = pd.read_csv(OUT_DIR / "full_results.csv")

NAVY = "#13233F"
TEAL = "#028090"
MINT = "#02C39A"
AMBER = "#E8A93A"
CORAL = "#E85C4A"
SLATE = "#3C4A5E"

VARIANT_LABELS = {
    "reactive": "Reactive\n(baseline)",
    "predictive_default": "Predictive\n(default)",
    "predictive_tuned": "Predictive\n(tuned)",
}
VARIANT_COLORS = {"reactive": "#9AA6B5", "predictive_default": CORAL, "predictive_tuned": MINT}

# ===================== Chart 1: Metric comparison bars =====================
fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
metrics = [("recall", "Recall", "{:.0%}"), ("false_positive_rate", "False Positive Rate", "{:.0%}"),
           ("f1_score", "F1 Score", "{:.2f}")]

variants = ["reactive", "predictive_default", "predictive_tuned"]
for ax, (key, title, fmt) in zip(axes, metrics):
    vals = [summary[v][key] for v in variants]
    colors = [VARIANT_COLORS[v] for v in variants]
    bars = ax.bar([VARIANT_LABELS[v] for v in variants], vals, color=colors, width=0.6)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width()/2, b.get_height() + 0.02, fmt.format(v),
                ha='center', fontsize=10, fontweight='bold', color=NAVY)
    ax.set_title(title, fontsize=12, fontweight='bold', color=NAVY)
    ax.set_ylim(0, 1.15)
    ax.spines[['top', 'right']].set_visible(False)
    ax.tick_params(axis='x', labelsize=9.5)

fig.suptitle("TrustGuard-IoMT: Reactive vs. Predictive (Default & Tuned) \u2014 16 trials, 128 device-records each",
             fontsize=12.5, fontweight='bold', color=NAVY, y=1.03)
plt.tight_layout()
plt.savefig(OUT_DIR / "metric_comparison.png", dpi=180, bbox_inches='tight')
plt.close()
print("Saved metric_comparison.png")

# ===================== Chart 2: Detection latency distribution =====================
fig, ax = plt.subplots(figsize=(9, 4.5))
lat_data = []
labels = []
colors = []
for v in variants:
    sub = df[(df["variant"] == v) & (df["is_attacked"]) & (df["ever_flagged"])]
    lat_data.append(sub["detection_latency"].dropna().values)
    labels.append(VARIANT_LABELS[v])
    colors.append(VARIANT_COLORS[v])

bp = ax.boxplot(lat_data, labels=labels, patch_artist=True, widths=0.5,
                 medianprops=dict(color=NAVY, linewidth=2))
for patch, color in zip(bp['boxes'], colors):
    patch.set_facecolor(color)
    patch.set_alpha(0.75)

ax.axhline(0, color=CORAL, linestyle='--', linewidth=1, alpha=0.7)
ax.text(3.35, 1, "0 = caught exactly\nat attack onset", fontsize=8.5, color=CORAL, va='bottom')
ax.set_ylabel("Detection latency (steps BEFORE attack onset)", fontsize=10.5)
ax.set_title("How early is each system catching the attack?", fontsize=12.5, fontweight='bold', color=NAVY)
ax.spines[['top', 'right']].set_visible(False)
plt.tight_layout()
plt.savefig(OUT_DIR / "latency_distribution.png", dpi=180, bbox_inches='tight')
plt.close()
print("Saved latency_distribution.png")

# ===================== Chart 3: Confusion matrices =====================
fig, axes = plt.subplots(1, 3, figsize=(12, 3.6))
for ax, v in zip(axes, variants):
    s = summary[v]
    matrix = np.array([[s["tp"], s["fn"]], [s["fp"], s["tn"]]])
    im = ax.imshow(matrix, cmap="Blues", vmin=0, vmax=max(s["tp"]+s["fn"]+s["fp"]+s["tn"], 1))
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(matrix[i, j]), ha='center', va='center',
                     fontsize=14, fontweight='bold',
                     color='white' if matrix[i, j] > matrix.max()/2 else NAVY)
    ax.set_xticks([0, 1]); ax.set_xticklabels(["Flagged", "Not flagged"], fontsize=9)
    ax.set_yticks([0, 1]); ax.set_yticklabels(["Attacked", "Benign"], fontsize=9)
    ax.set_title(VARIANT_LABELS[v].replace("\n", " "), fontsize=11, fontweight='bold', color=NAVY)

fig.suptitle("Confusion Matrices (device-level, across all trials)", fontsize=12.5, fontweight='bold', color=NAVY)
plt.tight_layout()
plt.savefig(OUT_DIR / "confusion_matrices.png", dpi=180, bbox_inches='tight')
plt.close()
print("Saved confusion_matrices.png")

print("\nAll charts generated in outputs/evaluation/")
