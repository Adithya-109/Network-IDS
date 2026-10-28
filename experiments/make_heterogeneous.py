"""Generates a heterogeneous-host scenario: a PCAP plus labels.csv.

One fixed threshold cannot fit every host here. Busy but legitimate hosts
run above the static thresholds all the time:

    10.0.1.5  web proxy          ~60 SYN / 5 s (slow +-15% daily-style swing)
    10.0.1.6  service monitor    probes the same 20 ports every 5 s
    10.0.1.7  DNS resolver       ~80 UDP / 5 s
    10.0.1.8  ping monitor       ~40 ICMP echo / 5 s

while ten quiet clients (10.0.2.10-19) make a few connections, DNS lookups
and pings. After the training period, three of the quiet clients are
compromised and attack *below* the static thresholds, yet far above their
own normal behaviour:

    lowrate_synflood  10.0.2.11  25 SYN / 5 s        (static SYN flood: 40)
    slow_portscan     10.0.2.12  10 new ports / 5 s  (static port scan: 15)
    lowrate_udpflood  10.0.2.13  35 UDP / 5 s        (static UDP flood: 50)

    python experiments/make_heterogeneous.py --out data/hetero --seed 1
"""

import argparse
import csv
import math
import os
import random
import sys

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, PcapWriter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments.make_poisoning import client_syns
from experiments.make_synthetic import BASE_TS, SERVER

WINDOW = 5.0
PROXY, MONITOR, RESOLVER, PINGER = "10.0.1.5", "10.0.1.6", "10.0.1.7", "10.0.1.8"
QUIET = [f"10.0.2.{i}" for i in range(10, 20)]
SYN_ATTACKER, SCAN_ATTACKER, UDP_ATTACKER = "10.0.2.11", "10.0.2.12", "10.0.2.13"
MONITOR_PORTS = [22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 3306, 5432, 6379,
                 8080, 8443, 9000, 9200, 27017]


def poisson(rng, lam):
    # Knuth's method; fine for the small rates used here.
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def udp_burst(rng, src, dst, t, n, width, dport=53):
    return [(t + rng.uniform(0, width * 0.999),
             IP(src=src, dst=dst) / UDP(sport=rng.randint(1024, 65535), dport=dport) / Raw(b"\x12\x34q"))
            for _ in range(n)]


def busy_hosts(rng, duration):
    pkts = []
    t = 0.0
    while t < duration:
        swing = 1 + 0.15 * math.sin(2 * math.pi * t / 600.0)
        pkts += client_syns(rng, PROXY, t, poisson(rng, 60 * swing), WINDOW)
        for port in MONITOR_PORTS:
            ts = t + rng.uniform(0, WINDOW * 0.999)
            pkts.append((ts, IP(src=MONITOR, dst=SERVER) / TCP(sport=rng.randint(1024, 65535), dport=port, flags="S")))
            pkts.append((ts + 0.0005, IP(src=SERVER, dst=MONITOR) / TCP(sport=port, dport=40000, flags="RA")))
        pkts += udp_burst(rng, RESOLVER, "10.0.0.53", t, poisson(rng, 80 * swing), WINDOW)
        for _ in range(poisson(rng, 40)):
            dst = f"10.0.2.{rng.randint(10, 19)}"
            pkts.append((t + rng.uniform(0, WINDOW * 0.999), IP(src=PINGER, dst=dst) / ICMP()))
        t += WINDOW
    return pkts


def quiet_hosts(rng, duration):
    pkts = []
    for host in QUIET:
        t = 0.0
        while t < duration:
            pkts += client_syns(rng, host, t, poisson(rng, 3), WINDOW)
            pkts += udp_burst(rng, host, "10.0.1.7", t, poisson(rng, 1), WINDOW)
            if rng.random() < 0.05:
                pkts.append((t + rng.uniform(0, WINDOW), IP(src=host, dst=SERVER) / ICMP()))
            t += WINDOW
    return pkts


def attacks(rng, start):
    pkts, episodes = [], []

    t0, t = start, start
    while t < t0 + 60:
        pkts += [(ts, p) for ts, p in client_syns(rng, SYN_ATTACKER, t, 25, WINDOW)
                 if p[TCP].flags == "S"]  # half-open: SYNs only, no handshake completion
        t += WINDOW
    episodes.append(("lowrate_synflood", SYN_ATTACKER, t0, t))

    t0 = t = start + 100
    ports = iter(rng.sample(range(1, 65535), 200))
    while t < t0 + 60:
        for _ in range(10):
            ts = t + rng.uniform(0, WINDOW * 0.999)
            pkts.append((ts, IP(src=SCAN_ATTACKER, dst=SERVER) / TCP(sport=rng.randint(1024, 65535),
                                                                    dport=next(ports), flags="S")))
        t += WINDOW
    episodes.append(("slow_portscan", SCAN_ATTACKER, t0, t))

    t0 = t = start + 200
    while t < t0 + 60:
        pkts += udp_burst(rng, UDP_ATTACKER, SERVER, t, 35, WINDOW, dport=rng.choice([53, 123, 161]))
        t += WINDOW
    episodes.append(("lowrate_udpflood", UDP_ATTACKER, t0, t))
    return pkts, episodes


def generate(out_dir, seed=1, train=300.0, gap=60.0):
    rng = random.Random(seed)
    attack_start = train + gap
    duration = attack_start + 200 + 60 + 60
    pkts = busy_hosts(rng, duration) + quiet_hosts(rng, duration)
    attack_pkts, episodes = attacks(rng, attack_start)
    pkts += attack_pkts
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
            w.writerow([label, src, f"{BASE_TS + start:.6f}", f"{BASE_TS + end - 0.001:.6f}"])
    return pcap_path, labels_path, len(pkts)


def main():
    parser = argparse.ArgumentParser(description="Generate a labelled heterogeneous-host scenario.")
    parser.add_argument("--out", default="data/hetero")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--train", type=float, default=300.0, help="Attack-free seconds at the start.")
    args = parser.parse_args()
    pcap, labels, n = generate(args.out, seed=args.seed, train=args.train)
    print(f"wrote {n} packets -> {pcap}\nlabels -> {labels}")


if __name__ == "__main__":
    main()
