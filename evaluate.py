"""Scores a replay run (see replay.py) against ground-truth attack episodes.

    python evaluate.py results/full --labels data/synthetic/labels.csv --window 5

Ground truth is a CSV of attack episodes, one row per attacker and interval:

    label,src_ip,start,end
    portscan,10.0.0.66,1700000120,1700000126
    synflood,192.168.10.0/24,2017-07-07T15:56:00-03:00,2017-07-07T16:16:00-03:00

``src_ip`` is an address or CIDR; ``start``/``end`` are epoch seconds or ISO
8601 timestamps (give a UTC offset; naive ones are read as UTC).

Two views are reported:

* Window level. Each (time window, source IP) that sent at least one packet
  is one unit. It is an attack unit when it overlaps an episode of that
  source, and predicted positive when that source raised any alert in it.
  Gives precision / recall / F1 / FPR, overall and per detection layer.
* Episode level. An episode counts as detected when its source raised an
  alert between ``start`` and ``end + grace``; time-to-detect is measured
  from ``start`` to that first alert.
"""

import argparse
import csv
import ipaddress
import json
import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone


def parse_time(value):
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()


class Episode:
    def __init__(self, label, src, start, end):
        self.label = label
        self.src = src
        self.network = ipaddress.ip_network(src, strict=False)
        self.start = start
        self.end = end

    def matches(self, ip):
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False


def load_labels(path):
    episodes = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            start, end = parse_time(row["start"]), parse_time(row["end"])
            if end < start:
                raise ValueError(f"episode ends before it starts: {row}")
            episodes.append(Episode(row["label"].strip(), row["src_ip"].strip(), start, end))
    return episodes


def load_run(run_dir):
    traffic = []
    with open(os.path.join(run_dir, "traffic.csv"), newline="") as f:
        for row in csv.DictReader(f):
            traffic.append((int(row["second"]), row["src_ip"], int(row["packets"])))
    alerts = []
    with open(os.path.join(run_dir, "alerts.jsonl")) as f:
        for line in f:
            if line.strip():
                alerts.append(json.loads(line))
    return traffic, alerts


def binary_metrics(tp, fp, fn, tn):
    def ratio(a, b):
        return a / b if b else None

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": ratio(fp, fp + tn),
        "accuracy": ratio(tp + tn, tp + fp + fn + tn),
    }


def evaluate(run_dir, labels_path, window=1, grace=None):
    """Returns the metrics dict for one run directory."""
    if window <= 0:
        raise ValueError("window must be positive")
    grace = window if grace is None else grace
    traffic, alerts = load_run(run_dir)
    episodes = load_labels(labels_path)

    # Episodes per exact source address, resolved once per distinct source.
    episodes_for = {}

    def src_episodes(ip):
        if ip not in episodes_for:
            episodes_for[ip] = [e for e in episodes if e.matches(ip)]
        return episodes_for[ip]

    def unit_of(ts, src):
        return (math.floor(ts / window), src)

    # Ground truth per unit: set of attack labels overlapping it (empty = benign).
    units = {}
    for sec, src, _ in traffic:
        unit = unit_of(sec, src)
        if unit in units:
            continue
        w_start, w_end = unit[0] * window, (unit[0] + 1) * window
        units[unit] = {e.label for e in src_episodes(src) if e.start < w_end and e.end >= w_start}

    # Predicted units, overall and per layer.
    predicted = set()
    predicted_by_layer = defaultdict(set)
    unmatched_alerts = 0
    for a in alerts:
        unit = unit_of(a["timestamp"], a["src_ip"])
        if unit not in units:
            unmatched_alerts += 1
            continue
        predicted.add(unit)
        predicted_by_layer[a.get("layer") or "unknown"].add(unit)

    def confusion(pred):
        tp = fp = fn = tn = 0
        for unit, labels in units.items():
            if labels:
                if unit in pred:
                    tp += 1
                else:
                    fn += 1
            elif unit in pred:
                fp += 1
            else:
                tn += 1
        return binary_metrics(tp, fp, fn, tn)

    per_label = {}
    for label in sorted({e.label for e in episodes}):
        label_units = [u for u, ls in units.items() if label in ls]
        hit = sum(1 for u in label_units if u in predicted)
        per_label[label] = {
            "units": len(label_units),
            "detected": hit,
            "recall": hit / len(label_units) if label_units else None,
        }

    # Episode-level detection and time-to-detect.
    alerts_by_src = defaultdict(list)
    for a in alerts:
        alerts_by_src[a["src_ip"]].append(a)
    for lst in alerts_by_src.values():
        lst.sort(key=lambda a: a["timestamp"])

    episode_rows = []
    for e in episodes:
        first = None
        for src, lst in alerts_by_src.items():
            if not e.matches(src):
                continue
            for a in lst:
                if e.start <= a["timestamp"] <= e.end + grace:
                    if first is None or a["timestamp"] < first["timestamp"]:
                        first = a
                    break
        episode_rows.append({
            "label": e.label,
            "src_ip": e.src,
            "start": e.start,
            "end": e.end,
            "detected": first is not None,
            "time_to_detect": first["timestamp"] - e.start if first else None,
            "first_detection": first["detection_type"] if first else None,
        })
    detected = [r for r in episode_rows if r["detected"]]
    ttd = sorted(r["time_to_detect"] for r in detected)

    return {
        "run_dir": run_dir,
        "labels": labels_path,
        "window_seconds": window,
        "grace_seconds": grace,
        "units": len(units),
        "attack_units": sum(1 for ls in units.values() if ls),
        "alerts": len(alerts),
        "alerts_outside_traffic": unmatched_alerts,
        "window_level": confusion(predicted),
        "per_layer": {layer: confusion(pred) for layer, pred in sorted(predicted_by_layer.items())},
        "per_label": per_label,
        "episode_level": {
            "episodes": len(episode_rows),
            "detected": len(detected),
            "detection_rate": len(detected) / len(episode_rows) if episode_rows else None,
            "mean_time_to_detect": sum(ttd) / len(ttd) if ttd else None,
            "median_time_to_detect": ttd[len(ttd) // 2] if ttd else None,
            "episodes": episode_rows,
        },
    }


def _fmt(v):
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.4f}"
    return str(v)


def print_report(m, out=sys.stdout):
    wl = m["window_level"]
    print(f"Run: {m['run_dir']}  (window={m['window_seconds']}s, {m['units']} units, "
          f"{m['attack_units']} attack units, {m['alerts']} alerts)", file=out)
    cols = ["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"]
    print(f"\n{'scope':<18}" + "".join(f"{c:>11}" for c in cols), file=out)
    print(f"{'ALL LAYERS':<18}" + "".join(f"{_fmt(wl[c]):>11}" for c in cols), file=out)
    for layer, lm in m["per_layer"].items():
        print(f"{layer:<18}" + "".join(f"{_fmt(lm[c]):>11}" for c in cols), file=out)

    print(f"\n{'attack label':<18}{'units':>8}{'detected':>10}{'recall':>10}", file=out)
    for label, lm in m["per_label"].items():
        print(f"{label:<18}{lm['units']:>8}{lm['detected']:>10}{_fmt(lm['recall']):>10}", file=out)

    el = m["episode_level"]
    print(f"\nEpisodes detected: {el['detected']}/{len(el['episodes'])}  "
          f"median time-to-detect: {_fmt(el['median_time_to_detect'])}s", file=out)
    for r in el["episodes"]:
        status = f"{r['time_to_detect']:.3f}s via {r['first_detection']}" if r["detected"] else "MISSED"
        print(f"  {r['label']:<14} {r['src_ip']:<18} {status}", file=out)
    if m["alerts_outside_traffic"]:
        print(f"\nwarning: {m['alerts_outside_traffic']} alerts did not map to a traffic unit", file=out)


def main():
    parser = argparse.ArgumentParser(description="Score a replay run against ground-truth episodes.")
    parser.add_argument("run_dir", help="Directory written by replay.py.")
    parser.add_argument("--labels", required=True, help="Ground-truth episode CSV.")
    parser.add_argument("--window", type=int, default=1, help="Evaluation window in seconds (default 1).")
    parser.add_argument("--grace", type=float, help="Seconds after an episode ends that still count (default: window).")
    parser.add_argument("--out", help="Where to write metrics JSON (default: <run_dir>/metrics.json).")
    parser.add_argument("--quiet", action="store_true", help="Only write the JSON.")
    args = parser.parse_args()

    m = evaluate(args.run_dir, args.labels, window=args.window, grace=args.grace)
    out = args.out or os.path.join(args.run_dir, "metrics.json")
    with open(out, "w") as f:
        json.dump(m, f, indent=2)
    if not args.quiet:
        print_report(m)
        print(f"\nmetrics -> {out}")


if __name__ == "__main__":
    main()
