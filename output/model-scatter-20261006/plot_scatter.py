"""Scatter plots for the 2026-10-06 grouped outer-CV training report."""

import json
from pathlib import Path
from pathlib import PureWindowsPath

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "model" / "static_ml_report.json"
OUT = Path(__file__).resolve().parent
data = json.loads(REPORT.read_text(encoding="utf-8"))
rows = [row for row in data["out_of_fold_samples"] if row["split"] == "outer_cv"]
assert len(rows) == data["sample_count"]

y = np.array([row["label"] for row in rows], dtype=int)
p = np.array([row["probability"] for row in rows], dtype=float)
families = np.array([row["family"] for row in rows])
rng = np.random.default_rng(20261006)
suspicious = data["development_suspicious_operating_point"]["threshold"]
malicious = data["development_malicious_operating_point"]["threshold"]
false_positives = sorted((row for row in rows if row["label"] == 0 and row["probability"] >= suspicious),
                         key=lambda row: row["probability"])
assert len(false_positives) == data["development_suspicious_operating_point"]["false_positive"]

plt.rcParams.update({"font.family": "Noto Sans SC", "font.size": 10,
                     "axes.spines.top": False, "axes.spines.right": False})


def finish(name, title, fig, ax):
    ax.set_title(title, loc="left", weight="bold", pad=14)
    fig.text(0.01, 0.005, f"Grouped 5-fold outer CV: n={len(rows):,} | Trained {data['trained_at_utc']}",
             color="#666666", fontsize=8)
    fig.savefig(OUT / name, dpi=180, bbox_inches="tight", facecolor="white")
    plt.close(fig)


# 1. Every outer-CV sample, separated by true binary label.
fig, ax = plt.subplots(figsize=(8.5, 5.5))
for label, x, color, caption in [(0, 0, "#3478b8", "Safe"), (1, 1, "#d64d42", "Malicious")]:
    values = p[y == label]
    ax.scatter(x + rng.uniform(-0.32, 0.32, len(values)), values, s=13, alpha=0.27,
               color=color, edgecolors="none", label=f"{caption} (n={len(values):,})")
ax.axhline(suspicious, color="#e69f00", linestyle="--", lw=1.6,
           label=f"Suspicious threshold {suspicious:.3f}")
ax.axhline(malicious, color="#7b4fa3", linestyle=":", lw=1.8,
           label=f"Malicious threshold {malicious:.3f}")
ax.scatter(rng.uniform(-0.28, 0.28, len(false_positives)),
           [row["probability"] for row in false_positives], s=45,
           facecolors="none", edgecolors="#d64d42", linewidths=1.1,
           label=f"False positives (n={len(false_positives)})", zorder=4)
ax.set(xlim=(-0.55, 1.55), ylim=(-0.03, 1.03), xticks=[0, 1],
       xticklabels=["Safe", "Malicious"], ylabel="Predicted malicious probability")
ax.grid(axis="y", alpha=0.18)
ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5), frameon=False)
finish("01-cv-probability.png", "Out-of-fold sample predictions", fig, ax)


# 2. Name every safe sample above the suspicious threshold.
fig, ax = plt.subplots(figsize=(10.5, 12.5))
for i, row in enumerate(false_positives):
    color = "#7b4fa3" if row["probability"] >= malicious else "#e69f00"
    ax.scatter(row["probability"], i, s=55, color=color, edgecolors="white",
               linewidths=0.5, zorder=3)
ax.axvline(suspicious, color="#e69f00", linestyle="--", lw=1.4,
           label=f"Suspicious threshold {suspicious:.3f}")
ax.axvline(malicious, color="#7b4fa3", linestyle=":", lw=1.7,
           label=f"Malicious threshold {malicious:.3f}")
ax.set(yticks=range(len(false_positives)),
       yticklabels=[PureWindowsPath(row["path"]).name for row in false_positives],
       xlim=(0.63, 1.01), xlabel="Out-of-fold malicious probability")
ax.tick_params(axis="y", length=0, labelsize=8)
ax.grid(axis="x", alpha=0.2)
ax.legend(loc="lower right", frameon=False)
finish("02-false-positive-files.png", f"False positives among {sum(y == 0):,} safe samples (n={len(false_positives)})", fig, ax)


# 2. Probability distribution for each true sample family.
labels = ["safe", "others-virus"] + sorted(
    (name for name in set(families) if name.startswith("virus/")),
    key=lambda name: (-np.sum(families == name), name),
)
fig, ax = plt.subplots(figsize=(11.5, 5.8))
for i, family in enumerate(labels):
    values = p[families == family]
    color = "#3478b8" if family == "safe" else "#d64d42"
    ax.scatter(i + rng.uniform(-0.28, 0.28, len(values)), values, s=12,
               alpha=0.28 if family == "safe" else 0.56, color=color, edgecolors="none")
    ax.plot([i - 0.19, i + 0.19], [np.median(values)] * 2, color="#161616", lw=2)
ax.axhline(suspicious, color="#e69f00", linestyle="--", lw=1.5,
           label=f"Suspicious threshold {suspicious:.3f}")
ax.set(ylim=(-0.03, 1.03), xlim=(-0.55, len(labels) - 0.45),
       xticks=range(len(labels)),
       xticklabels=[f"{name.replace('virus/', '')}\n(n={np.sum(families == name)})" for name in labels],
       ylabel="Predicted malicious probability", xlabel="True sample family")
ax.grid(axis="y", alpha=0.18)
ax.legend(frameon=False, loc="lower right")
finish("03-family-probability.png", "Out-of-fold probabilities by true family (black bars: medians)", fig, ax)


# 3. Observed false-positive rate and recall at a range of thresholds.
thresholds = np.unique(np.r_[np.linspace(0, 1, 101), suspicious, malicious])
fpr = np.array([np.mean(p[y == 0] >= t) for t in thresholds])
recall = np.array([np.mean(p[y == 1] >= t) for t in thresholds])
fig, ax = plt.subplots(figsize=(8.5, 5.8))
points = ax.scatter(100 * fpr, 100 * recall, c=thresholds, cmap="viridis_r", s=24,
                    alpha=0.78, edgecolors="none")
for t, title, color in [(suspicious, "Suspicious", "#e69f00"),
                        (malicious, "Malicious", "#7b4fa3")]:
    xval = 100 * np.mean(p[y == 0] >= t)
    yval = 100 * np.mean(p[y == 1] >= t)
    ax.scatter([xval], [yval], s=115, color=color, edgecolors="black", linewidth=0.8, zorder=5)
    ax.annotate(f"{title}: t={t:.3f}\nFPR {xval:.2f}%, recall {yval:.2f}%",
                (xval, yval), xytext=(10, 10 if title == "Suspicious" else -35),
                textcoords="offset points", fontsize=9)
ax.set(xlabel="False-positive rate among safe samples (%)",
       ylabel="Recall among malicious samples (%)", xlim=(-0.7, 25), ylim=(70, 101))
ax.grid(alpha=0.18)
fig.colorbar(points, ax=ax, label="Probability threshold", pad=0.02)
finish("04-threshold-tradeoff.png", "Threshold tradeoff across outer folds (zoomed)", fig, ax)


# 4. Reliability scatter: each marker is one equal-count probability bin.
order = np.argsort(p)
bins = np.array_split(order, 15)
avg_p = np.array([p[idx].mean() for idx in bins])
observed = np.array([y[idx].mean() for idx in bins])
fig, ax = plt.subplots(figsize=(6.8, 6.2))
ax.plot([0, 1], [0, 1], color="#888888", linestyle="--", lw=1.2, label="Perfect calibration")
ax.scatter(avg_p, observed, color="#3478b8", s=75,
           edgecolors="#1f4d70", linewidth=0.6, zorder=3)
ax.set(xlim=(-0.03, 1.03), ylim=(-0.03, 1.03),
       xlabel="Mean predicted malicious probability",
       ylabel="Observed malicious fraction")
ax.grid(alpha=0.18)
ax.legend(frameon=False, loc="upper left")
finish("05-calibration.png", "Out-of-fold calibration (15 equal-count bins)", fig, ax)

print(f"Saved 5 plots to {OUT}")
