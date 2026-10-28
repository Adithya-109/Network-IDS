"""Offline PCAP replay for reproducible experiments.

Feeds one or more capture files through the same detection pipeline as live
capture, using each packet's capture timestamp as the clock. No root, no
network access, no dashboard database writes and no model.joblib reuse, so
the same PCAP + config + seed always produces the same alerts.

    python replay.py capture.pcap --config experiments/configs/full.json --out results/full

Writes into --out:
    alerts.jsonl   one JSON alert per line
    traffic.csv    packets per (second, src_ip), the evaluation's denominator
    run.json       config, input hashes, versions, timing and throughput
    thresholds.csv with --trace-thresholds: every baseline sample with the
                   tracker's mean, std, threshold and reference threshold
"""

import argparse
import csv
import hashlib
import json
import logging
import os
import platform
import random
import subprocess
import sys
import time
from collections import Counter
from importlib import metadata

import numpy as np
from scapy.all import PcapReader

from detector import DetectionEngine
from pipeline import parse_packet, analyze
from rules_loader import deep_merge

HERE = os.path.dirname(os.path.abspath(__file__))


def load_experiment(path):
    if not path:
        return {"name": "default", "overrides": {}}
    with open(path) as f:
        exp = json.load(f)
    exp.setdefault("name", os.path.splitext(os.path.basename(path))[0])
    exp.setdefault("overrides", {})
    return exp


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def environment_info():
    versions = {}
    for pkg in ("scapy", "scikit-learn", "numpy", "flask"):
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = None
    try:
        commit = subprocess.run(
            ["git", "-C", HERE, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        dirty = bool(subprocess.run(
            ["git", "-C", HERE, "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True,
        ).stdout.strip())
    except Exception:
        commit, dirty = None, None
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": versions,
        "git_commit": commit,
        "git_dirty": dirty,
    }


TRACE_FIELDS = ["t", "src_ip", "metric", "value", "accepted", "samples", "mean", "std",
                "threshold", "ref_threshold", "drifted"]


def run(pcaps, experiment, out_dir, rules_path=None, seed=None, limit=None, progress_every=100000,
        trace=False, trace_src=None):
    """Replays ``pcaps`` through a fresh offline engine and writes the run outputs to ``out_dir``."""
    rules_path = rules_path or os.path.join(HERE, "rules.json")
    seed = experiment.get("seed", 42) if seed is None else seed
    random.seed(seed)
    np.random.seed(seed)

    overrides = deep_merge({}, experiment.get("overrides", {}))
    deep_merge(overrides, {"dynamic": {"model_learning": {"seed": seed}}})

    os.makedirs(out_dir, exist_ok=True)
    engine = DetectionEngine(rules_path=rules_path, overrides=overrides, offline=True)
    trace_f = None
    if trace:
        trace_f = open(os.path.join(out_dir, "thresholds.csv"), "w", newline="")
        trace_w = csv.DictWriter(trace_f, fieldnames=TRACE_FIELDS)
        trace_w.writeheader()
        wanted = set(trace_src) if trace_src else None

        def write_trace(row):
            if wanted is None or row["src_ip"] in wanted:
                trace_w.writerow(row)
        engine.trace = write_trace

    traffic = Counter()  # (second, src_ip) -> packets
    alert_counts = Counter()
    packets = ip_packets = out_of_order = 0
    first_ts = last_ts = None

    wall_start = time.perf_counter()
    with open(os.path.join(out_dir, "alerts.jsonl"), "w") as alerts_f:
        for pcap in pcaps:
            with PcapReader(pcap) as reader:
                for pkt in reader:
                    if limit is not None and packets >= limit:
                        break
                    packets += 1
                    ts = float(pkt.time)
                    if last_ts is not None and ts < last_ts:
                        out_of_order += 1
                    first_ts = ts if first_ts is None else first_ts
                    last_ts = ts if last_ts is None else max(last_ts, ts)

                    info = parse_packet(pkt)
                    if info is None:
                        continue
                    ip_packets += 1
                    traffic[(int(ts), info.src_ip)] += 1

                    for a in analyze(engine, info, ts):
                        alert_counts[a["detection_type"]] += 1
                        alerts_f.write(json.dumps(a, sort_keys=True) + "\n")

                    if progress_every and packets % progress_every == 0:
                        print(f"[replay] {packets} packets...", file=sys.stderr)
    wall_seconds = time.perf_counter() - wall_start
    engine.stop()
    if trace_f:
        trace_f.close()

    with open(os.path.join(out_dir, "traffic.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["second", "src_ip", "packets"])
        for (sec, src), n in sorted(traffic.items()):
            w.writerow([sec, src, n])

    summary = {
        "experiment": experiment,
        "seed": seed,
        "rules_path": os.path.relpath(rules_path, HERE),
        "rules_sha256": sha256_file(rules_path),
        "inputs": [{"path": p, "sha256": sha256_file(p)} for p in pcaps],
        "packets": packets,
        "ip_packets": ip_packets,
        "out_of_order_packets": out_of_order,
        "capture_start": first_ts,
        "capture_end": last_ts,
        "wall_seconds": round(wall_seconds, 3),
        "throughput_pps": round(packets / wall_seconds, 1) if wall_seconds > 0 else None,
        "alerts_by_type": dict(alert_counts),
        "environment": environment_info(),
    }
    with open(os.path.join(out_dir, "run.json"), "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
    return summary


def main():
    parser = argparse.ArgumentParser(description="Replay PCAP files through the NIDS offline.")
    parser.add_argument("pcaps", nargs="+", help="PCAP/PCAPNG files, replayed in the given order.")
    parser.add_argument("--config", help="Experiment config JSON (see experiments/configs/).")
    parser.add_argument("--out", required=True, help="Output directory for this run.")
    parser.add_argument("--rules", help="Rules file (default: rules.json next to this script).")
    parser.add_argument("--seed", type=int, help="Overrides the config's seed (for repeated runs).")
    parser.add_argument("--limit", type=int, help="Stop after this many packets.")
    parser.add_argument("--trace-thresholds", action="store_true",
                        help="Write every baseline sample to thresholds.csv.")
    parser.add_argument("--trace-src", nargs="+", help="Only trace these source IPs.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)
    experiment = load_experiment(args.config)
    s = run(args.pcaps, experiment, args.out, rules_path=args.rules, seed=args.seed, limit=args.limit,
            trace=args.trace_thresholds, trace_src=args.trace_src)
    print(f"[replay] {s['packets']} packets in {s['wall_seconds']}s ({s['throughput_pps']} pps), "
          f"{sum(s['alerts_by_type'].values())} alerts -> {args.out}")
    if s["out_of_order_packets"]:
        print(f"[replay] warning: {s['out_of_order_packets']} packets had earlier timestamps "
              f"than their predecessor; merge inputs with `mergecap` for time order.", file=sys.stderr)


if __name__ == "__main__":
    main()
