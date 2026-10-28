"""Aggregates evaluated runs into one table: mean, std and 95% CI per experiment.

    python summarize.py results/*/ --csv results/summary.csv

Each argument is a run directory containing run.json and metrics.json. Runs
are grouped by experiment name, so repeating a config with different --seed
values gives one row with confidence intervals across seeds.
"""

import argparse
import csv
import json
import math
import os
import sys
from collections import defaultdict

from scipy import stats

METRICS = [
    ("precision", lambda m: m["window_level"]["precision"]),
    ("recall", lambda m: m["window_level"]["recall"]),
    ("f1", lambda m: m["window_level"]["f1"]),
    ("fpr", lambda m: m["window_level"]["fpr"]),
    ("episode_detection_rate", lambda m: m["episode_level"]["detection_rate"]),
    ("median_ttd_s", lambda m: m["episode_level"]["median_time_to_detect"]),
]


def mean_ci(values, confidence=0.95):
    values = [v for v in values if v is not None]
    n = len(values)
    if n == 0:
        return None, None, None, 0
    mean = sum(values) / n
    if n == 1:
        return mean, None, None, 1
    std = math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))
    half = stats.t.ppf((1 + confidence) / 2, n - 1) * std / math.sqrt(n)
    return mean, std, half, n


def summarize(run_dirs):
    groups = defaultdict(list)
    for d in run_dirs:
        with open(os.path.join(d, "run.json")) as f:
            run = json.load(f)
        with open(os.path.join(d, "metrics.json")) as f:
            metrics = json.load(f)
        groups[run["experiment"]["name"]].append((run, metrics))

    rows = []
    for name, runs in sorted(groups.items()):
        row = {"experiment": name, "runs": len(runs), "seeds": sorted({r["seed"] for r, _ in runs})}
        for key, get in METRICS:
            mean, std, half, _ = mean_ci([get(m) for _, m in runs])
            row[key] = mean
            row[f"{key}_std"] = std
            row[f"{key}_ci95"] = half
        mean, _, _, _ = mean_ci([r["throughput_pps"] for r, _ in runs])
        row["throughput_pps"] = mean
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description="Aggregate evaluated runs by experiment.")
    parser.add_argument("run_dirs", nargs="+")
    parser.add_argument("--csv", help="Also write the table as CSV.")
    args = parser.parse_args()

    rows = summarize(args.run_dirs)
    header = f"{'experiment':<18}{'runs':>5}" + "".join(f"{k:>24}" for k, _ in METRICS)
    print(header)
    for r in rows:
        cells = []
        for k, _ in METRICS:
            if r[k] is None:
                cells.append(f"{'-':>24}")
            elif r[f"{k}_ci95"] is None:
                cells.append(f"{r[k]:>24.4f}")
            else:
                cells.append(f"{r[k]:>14.4f} ± {r[f'{k}_ci95']:<7.4f}")
        print(f"{r['experiment']:<18}{r['runs']:>5}" + "".join(cells))

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"\nsummary -> {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
