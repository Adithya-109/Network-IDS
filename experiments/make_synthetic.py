"""Generates a small labelled synthetic scenario: a PCAP plus labels.csv.

Benign hosts browse a web server, resolve DNS, ping occasionally and one of
them uses SSH; two attacker hosts run a port scan, a SYN flood, stealth
scans, DPI exploit payloads, a UDP flood and an ICMP flood at fixed offsets.
Packets are only written to a file (nothing is sent), so no root is needed.

It is a smoke test for the replay/evaluation pipeline and a controllable
testbed for threshold experiments, not a substitute for real datasets.

    python experiments/make_synthetic.py --out data/synthetic --seed 1
"""

import argparse
import csv
import os
import random

from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, PcapWriter

BASE_TS = 1_700_000_000.0  # fixed epoch so outputs are byte-identical per seed
SERVER = "10.0.0.1"
BENIGN_HOSTS = [f"10.0.0.{i}" for i in range(10, 20)]
SSH_USER = "10.0.0.10"
ATTACKER_A = "10.0.0.66"
ATTACKER_B = "10.0.0.77"


def benign_traffic(rng, duration):
    pkts = []
    for host in BENIGN_HOSTS:
        t = rng.uniform(0, 2)
        while t < duration:
            # One short HTTP(S) exchange: handshake, request, response, ACK.
            sport = rng.randint(30000, 60000)
            dport = rng.choice([80, 443])
            pkts.append((t, IP(src=host, dst=SERVER) / TCP(sport=sport, dport=dport, flags="S")))
            pkts.append((t + 0.001, IP(src=SERVER, dst=host) / TCP(sport=dport, dport=sport, flags="SA")))
            pkts.append((t + 0.002, IP(src=host, dst=SERVER) / TCP(sport=sport, dport=dport, flags="A")))
            path = rng.choice(["/", "/index.html", "/news", "/img/logo.png", "/api/items?page=2"])
            req = f"GET {path} HTTP/1.1\r\nHost: intranet.local\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
            pkts.append((t + 0.003, IP(src=host, dst=SERVER) / TCP(sport=sport, dport=dport, flags="PA") / Raw(req)))
            body = b"HTTP/1.1 200 OK\r\nContent-Length: 512\r\n\r\n" + bytes(rng.getrandbits(8) for _ in range(512))
            pkts.append((t + 0.010, IP(src=SERVER, dst=host) / TCP(sport=dport, dport=sport, flags="PA") / Raw(body)))
            pkts.append((t + 0.011, IP(src=host, dst=SERVER) / TCP(sport=sport, dport=dport, flags="FA")))
            t += rng.expovariate(0.8)  # ~0.8 connections/s per host
        t = rng.uniform(0, 5)
        while t < duration:
            pkts.append((t, IP(src=host, dst=SERVER) / UDP(sport=rng.randint(30000, 60000), dport=53) / Raw(b"\x12\x34query")))
            t += rng.expovariate(0.3)
        t = rng.uniform(0, 20)
        while t < duration:
            pkts.append((t, IP(src=host, dst=SERVER) / ICMP()))
            t += rng.expovariate(0.05)
    # One administrator keeps an SSH session open (benign use of a "suspicious" port).
    t = 30.0
    while t < duration:
        pkts.append((t, IP(src=SSH_USER, dst=SERVER) / TCP(sport=50022, dport=22, flags="PA") / Raw(b"\x00" * 48)))
        t += rng.expovariate(2.0)
    return pkts


def attack_traffic(rng, offset):
    """Returns (packets, episodes); episode times are relative to the scenario start."""
    pkts, episodes = [], []

    def episode(label, src, start, times_and_pkts):
        pkts.extend(times_and_pkts)
        end = max(t for t, _ in times_and_pkts)
        episodes.append((label, src, start, end))

    t0 = offset + 0
    ports = rng.sample(range(1, 10000), 200)
    episode("portscan", ATTACKER_A, t0,
            [(t0 + i * 0.02, IP(src=ATTACKER_A, dst=SERVER) / TCP(sport=rng.randint(1024, 65535), dport=p, flags="S"))
             for i, p in enumerate(ports)])

    t0 = offset + 60
    episode("synflood", ATTACKER_B, t0,
            [(t0 + i * 0.005, IP(src=ATTACKER_B, dst=SERVER) / TCP(sport=rng.randint(1024, 65535), dport=80, flags="S"))
             for i in range(1000)])

    t0 = offset + 120
    episode("stealthscan", ATTACKER_A, t0,
            [(t0 + i * 0.5, IP(src=ATTACKER_A, dst=SERVER) / TCP(sport=40000 + i, dport=80, flags=f))
             for i, f in enumerate([0, 0x01, 0x29, 0, 0x01, 0x29])])

    t0 = offset + 180
    payloads = [
        b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: intranet.local\r\n\r\n",
        b"POST /comment HTTP/1.1\r\n\r\n<script>alert('x')</script>",
        b"GET /api/exec?cmd=/bin/sh HTTP/1.1\r\n\r\n",
        b"GET /../../etc/passwd HTTP/1.1\r\n\r\n",
    ]
    episode("dpi_exploit", ATTACKER_B, t0,
            [(t0 + i * 1.0, IP(src=ATTACKER_B, dst=SERVER) / TCP(sport=41000 + i, dport=80, flags="PA") / Raw(p))
             for i, p in enumerate(payloads)])

    t0 = offset + 240
    episode("udpflood", ATTACKER_A, t0,
            [(t0 + i * 0.004, IP(src=ATTACKER_A, dst=SERVER) / UDP(sport=rng.randint(1024, 65535), dport=53))
             for i in range(1500)])

    t0 = offset + 300
    episode("icmpflood", ATTACKER_B, t0,
            [(t0 + i * 0.01, IP(src=ATTACKER_B, dst=SERVER) / ICMP()) for i in range(600)])
    return pkts, episodes


def generate(out_dir, seed=1, warmup=120.0, duration=480.0):
    rng = random.Random(seed)
    os.makedirs(out_dir, exist_ok=True)
    pkts = benign_traffic(rng, duration)
    attacks, episodes = attack_traffic(rng, offset=warmup)
    pkts.extend(attacks)
    pkts.sort(key=lambda tp: tp[0])

    pcap_path = os.path.join(out_dir, "scenario.pcap")
    with PcapWriter(pcap_path, sync=False) as w:
        for t, p in pkts:
            frame = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / p
            frame.time = BASE_TS + t
            w.write(frame)

    labels_path = os.path.join(out_dir, "labels.csv")
    with open(labels_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "src_ip", "start", "end"])
        for label, src, start, end in episodes:
            w.writerow([label, src, f"{BASE_TS + start:.6f}", f"{BASE_TS + end:.6f}"])
    return pcap_path, labels_path, len(pkts)


def main():
    parser = argparse.ArgumentParser(description="Generate a labelled synthetic PCAP scenario.")
    parser.add_argument("--out", default="data/synthetic")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--warmup", type=float, default=120.0, help="Benign-only seconds before the first attack.")
    parser.add_argument("--duration", type=float, default=480.0)
    args = parser.parse_args()
    pcap, labels, n = generate(args.out, seed=args.seed, warmup=args.warmup, duration=args.duration)
    print(f"wrote {n} packets -> {pcap}\nlabels -> {labels}")


if __name__ == "__main__":
    main()
