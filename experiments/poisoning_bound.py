"""White-box poisoning of each baseline tracker (worst case for the theorem).

After a benign warm-up, the attacker knows the current threshold T_n and
sends a window value just below it, so no window ever alerts and every one
is learned. This is the strongest "boiling frog" attacker against a gated
baseline. For the drift-bounded tracker the threshold must stay below
T_0 + n * (1 + k) * max_rise, and its drift alarm (optionally rolling the
baseline back) should fire long before the ceiling is reached.

    python experiments/poisoning_bound.py --out results/poisoning_bound
"""

import argparse
import csv
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from baselines import ThresholdParams, tracker_factory

# SYN_FLOOD limits from rules.json; max_rise = max_rise_frac (0.02) * floor.
PARAMS = ThresholdParams(k_sigma=3.0, floor=10, ceiling=100, static=40, warmup=50, max_rise=0.2)

METHODS = {
    "ema": {"method": "ema"},
    "mad": {"method": "mad"},
    "drift_bounded": {"method": "drift_bounded", "drift": {"rollback": False}},
    "drift_bounded_rollback": {"method": "drift_bounded", "drift": {"rollback": True}},
}


def simulate(name, th_cfg, params=PARAMS, benign_windows=100, attack_windows=300, margin=0.02,
             benign_mean=5.0, benign_sd=1.2, seed=1):
    rng = random.Random(seed)
    tracker = tracker_factory(th_cfg)()
    rollback = th_cfg.get("drift", {}).get("rollback", False)
    rows = []

    for _ in range(benign_windows):
        tracker.observe(max(0, round(rng.gauss(benign_mean, benign_sd))), params)
    t0 = tracker.threshold(params)

    first_alarm = None
    alarms = 0
    for n in range(1, attack_windows + 1):
        value = tracker.threshold(params) * (1 - margin)
        tracker.observe(value, params)
        drifted = hasattr(tracker, "drifted") and tracker.drifted(params)
        if drifted:
            alarms += 1
            first_alarm = first_alarm or n
            if rollback:
                tracker.rollback()
        ref = tracker.reference_threshold(params) if hasattr(tracker, "reference_threshold") else None
        rows.append({
            "method": name, "window": n, "value": round(value, 4),
            "threshold": round(tracker.threshold(params), 4),
            "ref_threshold": None if ref is None else round(ref, 4),
            "bound": round(min(params.ceiling, t0 + n * (1 + params.k_sigma) * params.max_rise), 4),
            "drift_alarm": int(drifted),
        })

    reach = next((r["window"] for r in rows if r["threshold"] >= 0.99 * params.ceiling), None)
    summary = {
        "method": name,
        "t0": round(t0, 3),
        "threshold_at_25": rows[24]["threshold"],
        "threshold_at_100": rows[99]["threshold"],
        "threshold_at_300": rows[-1]["threshold"],
        "windows_to_ceiling": reach,
        "first_drift_alarm": first_alarm,
        "drift_alarms": alarms,
        "bound_violations": sum(1 for r in rows if r["threshold"] > r["bound"] + 1e-9),
    }
    return rows, summary


def plot(rows_by_method, path, params=PARAMS):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7, 4))
    for name, rows in rows_by_method.items():
        ax.plot([r["window"] for r in rows], [r["threshold"] for r in rows], label=name, linewidth=1.6)
    bound = rows_by_method["drift_bounded"]
    ax.plot([r["window"] for r in bound], [r["bound"] for r in bound], "k--", linewidth=1,
            label="bound $T_0 + n(1+k)\\delta$")
    ax.axhline(params.static, color="grey", linestyle=":", linewidth=1, label="static threshold")
    ax.set_xlabel("attack windows n (attacker stays just below the threshold)")
    ax.set_ylabel("SYN threshold (per 5 s window)")
    ax.set_ylim(0, params.ceiling * 1.05)
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description="White-box poisoning of each baseline tracker.")
    parser.add_argument("--out", default="results/poisoning_bound")
    parser.add_argument("--windows", type=int, default=300)
    parser.add_argument("--seed", type=int, default=1)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rows_by_method, summaries = {}, []
    for name, cfg in METHODS.items():
        rows, summary = simulate(name, cfg, attack_windows=args.windows, seed=args.seed)
        rows_by_method[name] = rows
        summaries.append(summary)

    with open(os.path.join(args.out, "trajectories.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows_by_method["ema"][0].keys()))
        w.writeheader()
        for rows in rows_by_method.values():
            w.writerows(rows)
    with open(os.path.join(args.out, "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summaries[0].keys()))
        w.writeheader()
        w.writerows(summaries)
    plot(rows_by_method, os.path.join(args.out, "threshold_under_poisoning.png"))

    cols = list(summaries[0].keys())
    print("".join(f"{c:>22}" for c in cols))
    for s in summaries:
        print("".join(f"{str(s[c]):>22}" for c in cols))
    print(f"\n-> {args.out}/")


if __name__ == "__main__":
    main()
