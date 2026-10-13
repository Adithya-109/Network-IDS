"""
=====================================================================
 DEMO / TEST TRAFFIC GENERATOR -- FOR LOCAL DETECTION DEMOS ONLY
=====================================================================
Generates controlled, safe traffic patterns aimed ONLY at your own
machine (127.0.0.1 by default) so you can trigger the NIDS detection
rules on demand without needing real attack traffic.

Requires the same Npcap + Administrator setup as the main app, because
it crafts raw packets with Scapy.

Usage (run in an Administrator PowerShell, with app.py already running
and monitoring started):

    python demo.py portscan
    python demo.py synflood
    python demo.py icmpflood
    python demo.py all

Optional: python demo.py portscan --target 127.0.0.1
=====================================================================
"""

import argparse
import sys
import time

from scapy.all import IP, TCP, UDP, ICMP, send, RandShort, Raw

BANNER = "[DEMO/TEST TRAFFIC]"


def run_portscan(target):
    # A realistic scan list: sequential low ports + a handful of the
    # "suspicious" service ports, so both Port Scan and Suspicious Port
    # Activity alerts fire together, just like a real scan would trigger.
    ports = list(range(2000, 2025)) + [21, 22, 23, 445, 3389]
    print(f"{BANNER} Port scan -> {target} across {len(ports)} ports")
    for i, port in enumerate(ports, 1):
        pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
        send(pkt, verbose=False)
        print(f"{BANNER}   SYN -> {target}:{port} ({i}/{len(ports)})")
        time.sleep(0.05)
    print(f"{BANNER} Port scan traffic complete.")


def run_synflood(target, port=80, count=100):
    print(f"{BANNER} SYN flood -> {target}:{port} ({count} packets)")
    pkt = IP(dst=target) / TCP(dport=port, flags="S", sport=RandShort())
    send(pkt, count=count, inter=0.01, verbose=False)
    print(f"{BANNER} SYN flood traffic complete.")


def run_icmpflood(target, count=100):
    print(f"{BANNER} ICMP flood -> {target} ({count} packets)")
    pkt = IP(dst=target) / ICMP()
    send(pkt, count=count, inter=0.02, verbose=False)
    print(f"{BANNER} ICMP flood traffic complete.")

def run_udpflood(target, count=100):
    print(f"{BANNER} UDP flood -> {target}:53 ({count} packets)")
    pkt = IP(dst=target) / UDP(dport=53, sport=RandShort())
    send(pkt, count=count, inter=0.01, verbose=False)
    print(f"{BANNER} UDP flood traffic complete.")

def run_stealthscan(target):
    print(f"{BANNER} TCP Stealth Scans -> {target}")
    scans = [
        ("NULL Scan", 0),
        ("FIN Scan", 0x01),
        ("XMAS Scan", 0x29) # FIN | PSH | URG
    ]
    for name, flag in scans:
        print(f"{BANNER}   Sending {name}...")
        pkt = IP(dst=target) / TCP(dport=80, flags=flag)
        send(pkt, verbose=False)
        time.sleep(0.5)
    print(f"{BANNER} Stealth scan traffic complete.")


def run_dpi_test(target):
    print(f"{BANNER} Deep Packet Inspection (DPI) Test -> {target}:80")
    payloads = [
        b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n",
        b"POST /comment HTTP/1.1\r\n\r\n<script>alert('XSS')</script>",
        b"GET /api/exec?cmd=/bin/sh HTTP/1.1\r\n\r\n"
    ]
    for i, p in enumerate(payloads, 1):
        pkt = IP(dst=target) / TCP(dport=80, flags="PA", sport=RandShort()) / Raw(load=p)
        send(pkt, verbose=False)
        print(f"{BANNER}   Sent Malicious Payload {i}/3")
        time.sleep(0.5)
    print(f"{BANNER} DPI traffic complete.")


def run_anomaly(target, count=40):
    print(f"{BANNER} Zero-Day / AI Anomaly Burst -> {target} ({count} packets)")
    # Sends rapid packets that bypass static signatures and volumetric rules,
    # forcing the Layer 3 Isolation Forest to detect the behavioral anomaly.
    pkt = IP(dst=target) / ICMP()
    send(pkt, count=count, inter=0.02, verbose=False)
    print(f"{BANNER} AI Anomaly traffic complete.")


def run_continuous(target, interval):
    print(f"{BANNER} Starting continuous attack simulation against {target} every {interval}s")
    print(f"{BANNER} Press Ctrl+C to stop.")
    try:
        while True:
            print(f"\n{BANNER} --- Starting new attack cycle ---")
            run_portscan(target)
            time.sleep(1)
            run_synflood(target, count=50)
            time.sleep(1)
            run_icmpflood(target, count=40)
            time.sleep(1)
            run_udpflood(target, count=60)
            time.sleep(1)
            run_stealthscan(target)
            time.sleep(1)
            run_dpi_test(target)
            time.sleep(1)
            run_anomaly(target)
            
            print(f"\n{BANNER} Cycle complete. Sleeping for {interval} seconds...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n{BANNER} Continuous mode stopped.")


def main():
    parser = argparse.ArgumentParser(
        description="Generate safe, local DEMO/TEST traffic to trigger NIDS alerts."
    )
    parser.add_argument(
        "mode",
        choices=["portscan", "synflood", "icmpflood", "udpflood", "stealthscan", "dpi", "anomaly", "all", "continuous"],
        help="Which attack pattern to simulate.",
    )
    parser.add_argument(
        "--target",
        default="127.0.0.1",
        help="Target IP -- keep this at 127.0.0.1 or another IP of your own machine. Default: 127.0.0.1",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=15,
        help="Seconds to wait between cycles in continuous mode (default: 15).",
    )
    args = parser.parse_args()

    print(f"{BANNER} Target: {args.target}  (make sure this is YOUR OWN machine)")
    print(f"{BANNER} Make sure the NIDS dashboard is running and monitoring is started.\n")

    try:
        if args.mode == "continuous":
            run_continuous(args.target, args.interval)
            return

        if args.mode in ("portscan", "all"):
            run_portscan(args.target)
            time.sleep(1)
        if args.mode in ("synflood", "all"):
            run_synflood(args.target)
            time.sleep(1)
        if args.mode in ("icmpflood", "all"):
            run_icmpflood(args.target)
            time.sleep(1)
        if args.mode in ("udpflood", "all"):
            run_udpflood(args.target)
            time.sleep(1)
        if args.mode in ("stealthscan", "all"):
            run_stealthscan(args.target)
            time.sleep(1)
        if args.mode in ("dpi", "all"):
            run_dpi_test(args.target)
            time.sleep(1)
        if args.mode in ("anomaly", "all"):
            run_anomaly(args.target)
    except PermissionError:
        print(
            "\nPermissionError: sending raw packets needs Administrator rights.\n"
            "Close this terminal and re-run it as Administrator."
        )
        sys.exit(1)

    print(f"\n{BANNER} Done. Check the dashboard for new alerts.")


if __name__ == "__main__":
    main()
