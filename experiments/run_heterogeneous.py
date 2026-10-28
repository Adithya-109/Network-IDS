"""Heterogeneous-host sweep: scenario seeds x configs in configs/heterogeneous/.

Scores each run after the training period (``--train`` seconds are excluded
from window-level metrics) and splits false positives into busy benign hosts
and quiet benign hosts, which is where static and adaptive thresholds differ.

    python experiments/run_heterogeneous.py --seeds 1 2 3
"""

import argparse
import csv
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evaluate
import replay
from experiments.make_heterogeneous import (MONITOR, PINGER, PROXY, QUIET, RESOLVER, generate)
from summarize import mean_ci

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = ["lowrate_synflood", "slow_portscan", "lowrate_udpflood"]
BUSY = {PROXY, MONITOR, RESOLVER, PINGER}
KEYS = [f"{l}_recall" for l in LABELS] + ["precision", "fpr", "fp_busy", "fp_quiet"]


def run_sweep(seeds, data_dir, out_dir, train=300.0, window=5):
    configs = sorted(glob.glob(os.path.join(HERE, "configs", "heterogeneous", "*.json")))
    rows = []
    for seed in seeds:
        scen = os.path.join(data_dir, f"s{seed}")
        pcap, labels, _ = generate(scen, seed=seed, train=train)
        for cfg_path in configs:
            exp = replay.load_experiment(cfg_path)
            run_dir = os.path.join(out_dir, f"s{seed}", exp["name"])
            replay.run([pcap], exp, run_dir, progress_every=0)
            m = evaluate.evaluate(run_dir, labels, window=window, exclude_first=train)
            with open(os.path.join(run_dir, "metrics.json"), "w") as f:
                json.dump(m, f, indent=2)
            fps = m["false_positive_units_by_src"]
            row = {"config": exp["name"], "seed": seed}
            for label in LABELS:
                row[f"{label}_recall"] = m["per_label"][label]["recall"]
            row["precision"] = m["window_level"]["precision"]
            row["fpr"] = m["window_level"]["fpr"]
            row["fp_busy"] = sum(n for src, n in fps.items() if src in BUSY)
            row["fp_quiet"] = sum(n for src, n in fps.items() if src in QUIET)
            rows.append(row)
            print(f"[hetero] s{seed} {exp['name']:<25} " +
                  " ".join(f"{k}={row[k]:.2f}" if isinstance(row[k], float) else f"{k}={row[k]}"
                           for k in KEYS if row[k] is not None), file=sys.stderr)
    return rows


def aggregate(rows):
    groups = {}
    for r in rows:
        groups.setdefault(r["config"], []).append(r)
    out = []
    for cfg, rs in sorted(groups.items()):
        agg = {"config": cfg, "runs": len(rs)}
        for k in KEYS:
            mean, _, half, _ = mean_ci([r[k] for r in rs])
            agg[k], agg[f"{k}_ci95"] = mean, half
        out.append(agg)
    return out


def plot(agg, path):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    names = [a["config"] for a in agg]
    x = range(len(names))
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4))
    width = 0.27
    for i, label in enumerate(LABELS):
        k = f"{label}_recall"
        means = [a[k] or 0 for a in agg]
        cis = [a[f"{k}_ci95"] or 0 for a in agg]
        # Clip the t-interval to the valid [0, 1] range of a recall.
        yerr = [[min(c, m) for m, c in zip(means, cis)], [min(c, 1 - m) for m, c in zip(means, cis)]]
        ax1.bar([xi + (i - 1) * width for xi in x], means, width, yerr=yerr, label=label, capsize=2)
    ax1.set_ylabel("recall (5 s windows)")
    ax1.set_ylim(0, 1.05)
    ax1.set_title("Attacks below the static thresholds")
    ax1.legend(fontsize=7)
    ax2.bar([xi - 0.2 for xi in x], [a["fp_busy"] for a in agg], 0.4, label="busy benign hosts",
            yerr=[a["fp_busy_ci95"] or 0 for a in agg], capsize=2)
    ax2.bar([xi + 0.2 for xi in x], [a["fp_quiet"] for a in agg], 0.4, label="quiet benign hosts",
            yerr=[a["fp_quiet_ci95"] or 0 for a in agg], capsize=2)
    ax2.set_ylabel("false-positive windows (after training)")
    ax2.set_title("False positives")
    ax2.legend(fontsize=7)
    for ax in (ax1, ax2):
        ax.set_xticks(list(x))
        ax.set_xticklabels(names, rotation=30, ha="right", fontsize=8)
        ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="Heterogeneous-host sweep.")
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--train", type=float, default=300.0)
    parser.add_argument("--data", default="data/hetero")
    parser.add_argument("--out", default="results/hetero")
    args = parser.parse_args()

    rows = run_sweep(args.seeds, args.data, args.out, train=args.train)
    os.makedirs(args.out, exist_ok=True)
    for name, data in (("sweep.csv", rows), ("sweep_summary.csv", aggregate(rows))):
        with open(os.path.join(args.out, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
    agg = aggregate(rows)
    plot(agg, os.path.join(args.out, "heterogeneous.png"))

    def cell(a, k, fmt="{:.2f}"):
        if a[k] is None:
            return "-"
        ci = a[f"{k}_ci95"]
        return fmt.format(a[k]) + (("±" + fmt.format(ci)) if ci is not None else "")

    print(f"{'config':<26}{'syn_flood':>12}{'port_scan':>12}{'udp_flood':>12}{'precision':>12}{'fp_busy':>14}{'fp_quiet':>12}")
    for a in agg:
        print(f"{a['config']:<26}{cell(a, 'lowrate_synflood_recall'):>12}{cell(a, 'slow_portscan_recall'):>12}"
              f"{cell(a, 'lowrate_udpflood_recall'):>12}{cell(a, 'precision'):>12}"
              f"{cell(a, 'fp_busy', '{:.1f}'):>14}{cell(a, 'fp_quiet', '{:.1f}'):>12}")
    print(f"\n-> {args.out}/sweep.csv, sweep_summary.csv, heterogeneous.png")


if __name__ == "__main__":
    main()
