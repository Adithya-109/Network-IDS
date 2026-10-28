"""ML-layer sweep: scenario seeds x configs in configs/ml/.

The scenario is make_synthetic.py with a long benign warm-up and the attack
sequence played twice. Window-level metrics count ML alerts only and skip
the warm-up; recall is split into round 1 and round 2, where a model that
learned round 1's attacks as normal would miss them. Throughput is the
replay rate with every layer running.

    python experiments/run_ml.py --seeds 1 2 3
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
from experiments.make_synthetic import generate
from summarize import mean_ci

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = ["precision", "recall", "fpr", "roc_auc", "pr_auc", "round1_recall", "round2_recall", "throughput_pps"]


def round_recalls(per_label):
    r1 = [v["recall"] for k, v in per_label.items() if "_r" not in k and v["recall"] is not None]
    r2 = [v["recall"] for k, v in per_label.items() if k.endswith("_r2") and v["recall"] is not None]
    avg = lambda xs: sum(xs) / len(xs) if xs else None
    return avg(r1), avg(r2)


def run_sweep(seeds, data_dir, out_dir, warmup=300.0, window=5, only=None):
    configs = sorted(glob.glob(os.path.join(HERE, "configs", "ml", "*.json")))
    if only:
        configs = [c for c in configs if os.path.splitext(os.path.basename(c))[0] in only]
    rows = []
    for seed in seeds:
        scen = os.path.join(data_dir, f"s{seed}")
        pcap, labels, _ = generate(scen, seed=seed, warmup=warmup, rounds=2)
        for cfg_path in configs:
            exp = replay.load_experiment(cfg_path)
            run_dir = os.path.join(out_dir, f"s{seed}", exp["name"])
            summary = replay.run([pcap], exp, run_dir, progress_every=0)
            m = evaluate.evaluate(run_dir, labels, window=window, exclude_first=warmup, layers={"ml"})
            with open(os.path.join(run_dir, "metrics.json"), "w") as f:
                json.dump(m, f, indent=2)
            wl, sl = m["window_level"], m["score_level"] or {}
            r1, r2 = round_recalls(m["per_label"])
            row = {"config": exp["name"], "seed": seed,
                   "precision": wl["precision"], "recall": wl["recall"], "fpr": wl["fpr"],
                   "roc_auc": sl.get("roc_auc"), "pr_auc": sl.get("pr_auc"),
                   "round1_recall": r1, "round2_recall": r2,
                   "throughput_pps": summary["throughput_pps"]}
            rows.append(row)
            print(f"[ml] s{seed} {exp['name']:<18} " + " ".join(
                f"{k}={row[k]:.3f}" for k in KEYS if row[k] is not None), file=sys.stderr)
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


def plot_curves(out_dir, seed, labels_path, path, warmup=300.0):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve, roc_curve

    episodes = evaluate.load_labels(labels_path)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    for run_dir in sorted(glob.glob(os.path.join(out_dir, f"s{seed}", "*"))):
        scores = os.path.join(run_dir, "scores.csv")
        if not os.path.exists(scores):
            continue
        y, s = [], []
        with open(scores, newline="") as f:
            rows = list(csv.DictReader(f))
        t0 = min(float(r["window_start"]) for r in rows)
        for r in rows:
            start, width = float(r["window_start"]), float(r["window_seconds"])
            if start < t0 + warmup:
                continue
            y.append(int(any(e.matches(r["src_ip"]) and e.start < start + width and e.end >= start for e in episodes)))
            s.append(float(r["score"]))
        if not any(y):
            continue
        name = os.path.basename(run_dir)
        fpr, tpr, _ = roc_curve(y, s)
        prec, rec, _ = precision_recall_curve(y, s)
        ax1.plot(fpr, tpr, label=name)
        ax2.plot(rec, prec, label=name)
    ax1.plot([0, 1], [0, 1], "k:", linewidth=0.8)
    ax1.set_xlabel("false-positive rate")
    ax1.set_ylabel("true-positive rate")
    ax1.set_title("ROC (ML windows after warm-up)")
    ax2.set_xlabel("recall")
    ax2.set_ylabel("precision")
    ax2.set_title("Precision-recall")
    for ax in (ax1, ax2):
        ax.grid(alpha=0.3)
        ax.legend(fontsize=7)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="ML-layer sweep.")
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--warmup", type=float, default=300.0)
    parser.add_argument("--data", default="data/ml")
    parser.add_argument("--out", default="results/ml")
    parser.add_argument("--configs", nargs="+", help="Only these config names (default: all in configs/ml/).")
    args = parser.parse_args()

    rows = run_sweep(args.seeds, args.data, args.out, warmup=args.warmup, only=args.configs)
    agg = aggregate(rows)
    os.makedirs(args.out, exist_ok=True)
    for name, data in (("sweep.csv", rows), ("sweep_summary.csv", agg)):
        with open(os.path.join(args.out, name), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0].keys()))
            w.writeheader()
            w.writerows(data)
    seed = args.seeds[0]
    plot_curves(args.out, seed, os.path.join(args.data, f"s{seed}", "labels.csv"),
                os.path.join(args.out, "roc_pr.png"), warmup=args.warmup)

    def cell(a, k, fmt="{:.3f}"):
        if a[k] is None:
            return "-"
        ci = a[f"{k}_ci95"]
        return fmt.format(a[k]) + (("±" + fmt.format(ci)) if ci is not None else "")

    cols = ["precision", "recall", "fpr", "roc_auc", "pr_auc", "round1_recall", "round2_recall"]
    print(f"{'config':<19}" + "".join(f"{c:>16}" for c in cols) + f"{'pkts/s':>16}")
    for a in agg:
        print(f"{a['config']:<19}" + "".join(f"{cell(a, c):>16}" for c in cols)
              + f"{cell(a, 'throughput_pps', '{:.0f}'):>16}")
    print(f"\n-> {args.out}/sweep.csv, sweep_summary.csv, roc_pr.png")


if __name__ == "__main__":
    main()
