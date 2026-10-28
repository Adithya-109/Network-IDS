"""Blind slow-ramp sweep: growth rates x scenario seeds x poisoning configs.

For every (growth, seed) it generates a make_poisoning.py scenario, replays it
under each config in experiments/configs/poisoning/, scores it at 5 s windows
and writes one row per run plus a mean ± 95% CI table per (config, growth).

    python experiments/run_poisoning.py --growth 0.02 0.05 0.10 --seeds 1 2 3
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
from experiments.make_poisoning import generate
from summarize import mean_ci

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = ["poison_ramp", "lowslow_flood", "fresh_ip_flood"]


def run_sweep(growths, seeds, data_dir, out_dir, window=5):
    configs = sorted(glob.glob(os.path.join(HERE, "configs", "poisoning", "*.json")))
    rows = []
    for g in growths:
        for seed in seeds:
            tag = f"g{g:g}_s{seed}"
            scen = os.path.join(data_dir, tag)
            pcap, labels, _, _ = generate(scen, seed=seed, growth=g)
            for cfg_path in configs:
                exp = replay.load_experiment(cfg_path)
                run_dir = os.path.join(out_dir, tag, exp["name"])
                replay.run([pcap], exp, run_dir, progress_every=0)
                m = evaluate.evaluate(run_dir, labels, window=window)
                with open(os.path.join(run_dir, "metrics.json"), "w") as f:
                    json.dump(m, f, indent=2)
                eps = {r["label"]: r for r in m["episode_level"]["episodes"]}
                row = {"config": exp["name"], "growth": g, "seed": seed}
                for label in LABELS:
                    row[f"{label}_recall"] = m["per_label"][label]["recall"]
                row["flood_ttd_s"] = eps["lowslow_flood"]["time_to_detect"]
                row["fpr"] = m["window_level"]["fpr"]
                row["fp"] = m["window_level"]["fp"]
                rows.append(row)
                print(f"[sweep] {tag} {exp['name']:<17} flood={row['lowslow_flood_recall']:.2f} "
                      f"fresh={row['fresh_ip_flood_recall']:.2f} fpr={row['fpr']:.4f}", file=sys.stderr)
    return rows


def aggregate(rows):
    keys = ["poison_ramp_recall", "lowslow_flood_recall", "fresh_ip_flood_recall", "fpr"]
    groups = {}
    for r in rows:
        groups.setdefault((r["config"], r["growth"]), []).append(r)
    out = []
    for (cfg, g), rs in sorted(groups.items()):
        agg = {"config": cfg, "growth": g, "runs": len(rs)}
        for k in keys:
            mean, _, half, _ = mean_ci([r[k] for r in rs])
            agg[k] = mean
            agg[f"{k}_ci95"] = half
        out.append(agg)
    return out


def main():
    parser = argparse.ArgumentParser(description="Blind slow-ramp poisoning sweep.")
    parser.add_argument("--growth", type=float, nargs="+", default=[0.02, 0.05, 0.10])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--data", default="data/poisoning")
    parser.add_argument("--out", default="results/poisoning")
    args = parser.parse_args()

    rows = run_sweep(args.growth, args.seeds, args.data, args.out)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "sweep.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    agg = aggregate(rows)
    with open(os.path.join(args.out, "sweep_summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(agg[0].keys()))
        w.writeheader()
        w.writerows(agg)

    def cell(a, k):
        if a[k] is None:
            return "-"
        return f"{a[k]:.2f}" + (f"±{a[k + '_ci95']:.2f}" if a[k + "_ci95"] is not None else "")

    print(f"{'config':<18}{'growth':>7}{'ramp':>13}{'flood':>13}{'fresh_ip':>13}{'fpr':>15}")
    for a in agg:
        print(f"{a['config']:<18}{a['growth']:>7g}{cell(a, 'poison_ramp_recall'):>13}"
              f"{cell(a, 'lowslow_flood_recall'):>13}{cell(a, 'fresh_ip_flood_recall'):>13}"
              f"{a['fpr']:>9.4f}±{(a['fpr_ci95'] or 0):.4f}")
    print(f"\n-> {args.out}/sweep.csv, sweep_summary.csv")


if __name__ == "__main__":
    main()
