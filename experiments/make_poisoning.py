"""Generates a baseline-poisoning scenario: a PCAP plus labels.csv.

Benign background traffic is the same as make_synthetic.py. On top of it:

* 10.0.0.88 behaves like a normal client (``--start-rate`` SYNs per window)
  during the warm-up, then raises its SYN rate by ``--growth`` per window
  ("boiling frog") until it reaches ``--peak`` and holds it. Windows below
  ``--malicious-rate`` are labelled ``poison_ramp``; from the first window at
  or above it the traffic is a ``lowslow_flood``.
* 10.0.0.99 is never seen before and floods at ``--fresh-rate`` SYNs per
  window (``fresh_ip_flood``), which targets the cold-start threshold.

    python experiments/make_poisoning.py --out data/poison_g05 --growth 0.05
"""

import argparse
import csv
import math
import os
import random
import sys

from scapy.all import Ether, IP, TCP, PcapWriter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.make_synthetic import BASE_TS, SERVER, benign_traffic

RAMP_ATTACKER = "10.0.0.88"
FRESH_ATTACKER = "10.0.0.99"


def client_syns(rng, src, t, n, width):
    """n SYN -> SYN-ACK -> ACK exchanges spread over [t, t + width)."""
    pkts = []
    for _ in range(n):
        ts = t + rng.uniform(0, width * 0.999)
        sport, dport = rng.randint(1024, 65535), rng.choice([80, 443])
        pkts.append((ts, IP(src=src, dst=SERVER) / TCP(sport=sport, dport=dport, flags="S")))
        pkts.append((ts + 0.0005, IP(src=SERVER, dst=src) / TCP(sport=dport, dport=sport, flags="SA")))
        pkts.append((ts + 0.0010, IP(src=src, dst=SERVER) / TCP(sport=sport, dport=dport, flags="A")))
    return pkts


def generate(out_dir, seed=1, growth=0.05, start_rate=5.0, peak=90.0, malicious_rate=40.0,
             warmup=300.0, hold=60.0, fresh_rate=60.0, fresh_duration=20.0, window=5.0):
    if growth <= 0:
        raise ValueError("growth must be positive")
    rng = random.Random(seed)
    pkts, episodes = [], []

    # Ramp attacker: normal client during warm-up, then a geometric ramp.
    t = 0.0
    while t < warmup:
        pkts += client_syns(rng, RAMP_ATTACKER, t, rng.choice([4, 5, 5, 6]), window)
        t += window
    ramp_start, rate, t_cross = t, start_rate, None
    while rate < peak:
        if t_cross is None and rate >= malicious_rate:
            t_cross = t
        pkts += client_syns(rng, RAMP_ATTACKER, t, round(rate), window)
        rate *= 1 + growth
        t += window
    if t_cross is None:
        t_cross = t
    hold_end = t + hold
    while t < hold_end:
        pkts += client_syns(rng, RAMP_ATTACKER, t, round(peak), window)
        t += window
    episodes.append(("poison_ramp", RAMP_ATTACKER, ramp_start, t_cross))
    episodes.append(("lowslow_flood", RAMP_ATTACKER, t_cross, hold_end))

    # Fresh attacker: first packet ever is the flood.
    fresh_start = hold_end + 30.0
    t = fresh_start
    while t < fresh_start + fresh_duration:
        pkts += client_syns(rng, FRESH_ATTACKER, t, round(fresh_rate), window)
        t += window
    episodes.append(("fresh_ip_flood", FRESH_ATTACKER, fresh_start, t))

    duration = t + 60.0
    pkts += benign_traffic(rng, duration)
    pkts.sort(key=lambda tp: tp[0])

    os.makedirs(out_dir, exist_ok=True)
    pcap_path = os.path.join(out_dir, "scenario.pcap")
    with PcapWriter(pcap_path, sync=False) as w:
        for ts, p in pkts:
            frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / p
            frame.time = BASE_TS + ts
            w.write(frame)

    labels_path = os.path.join(out_dir, "labels.csv")
    with open(labels_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "src_ip", "start", "end"])
        for label, src, start, end in episodes:
            # Labels end on the last packet, not the window boundary after it.
            w.writerow([label, src, f"{BASE_TS + start:.6f}", f"{BASE_TS + end - 0.001:.6f}"])

    ramp_windows = math.ceil(math.log(peak / start_rate) / math.log(1 + growth))
    return pcap_path, labels_path, len(pkts), ramp_windows


def main():
    parser = argparse.ArgumentParser(description="Generate a labelled baseline-poisoning scenario.")
    parser.add_argument("--out", default="data/poisoning")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--growth", type=float, default=0.05, help="SYN-rate growth per window (0.05 = 5%%).")
    parser.add_argument("--start-rate", type=float, default=5.0, help="SYNs per window before the ramp.")
    parser.add_argument("--peak", type=float, default=90.0, help="SYNs per window the ramp ends at.")
    parser.add_argument("--malicious-rate", type=float, default=40.0,
                        help="SYNs per window from which ramp traffic is labelled a flood.")
    parser.add_argument("--warmup", type=float, default=300.0)
    parser.add_argument("--hold", type=float, default=60.0, help="Seconds the peak rate is held.")
    parser.add_argument("--fresh-rate", type=float, default=60.0, help="SYNs per window from the fresh IP.")
    args = parser.parse_args()
    pcap, labels, n, windows = generate(
        args.out, seed=args.seed, growth=args.growth, start_rate=args.start_rate, peak=args.peak,
        malicious_rate=args.malicious_rate, warmup=args.warmup, hold=args.hold, fresh_rate=args.fresh_rate)
    print(f"wrote {n} packets ({windows} ramp windows) -> {pcap}\nlabels -> {labels}")


if __name__ == "__main__":
    main()
