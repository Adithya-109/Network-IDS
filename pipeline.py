"""Per-packet analysis shared by live capture (sniffer.py) and offline PCAP
replay (replay.py), so both paths run exactly the same detection logic."""

from dataclasses import dataclass
from typing import Optional

from scapy.all import IP, TCP, UDP, ICMP, Raw


@dataclass
class PacketInfo:
    src_ip: str
    dst_ip: str
    proto: str  # "TCP", "UDP", "ICMP" or "OTHER"
    length: int
    sport: Optional[int] = None
    dport: Optional[int] = None
    flags: Optional[int] = None  # TCP flags as an int bitmask
    payload: Optional[bytes] = None

    @property
    def is_syn(self):
        # SYN set, ACK clear
        return self.flags is not None and bool(self.flags & 0x02) and not bool(self.flags & 0x10)


def parse_packet(pkt):
    """Extracts the fields the detector needs; returns None for non-IP packets."""
    if IP not in pkt:
        return None
    ip_layer = pkt[IP]
    info = PacketInfo(src_ip=ip_layer.src, dst_ip=ip_layer.dst, proto="OTHER", length=len(pkt))
    if TCP in pkt:
        info.proto = "TCP"
        info.sport = int(pkt[TCP].sport)
        info.dport = int(pkt[TCP].dport)
        info.flags = int(pkt[TCP].flags)
    elif UDP in pkt:
        info.proto = "UDP"
        info.sport = int(pkt[UDP].sport)
        info.dport = int(pkt[UDP].dport)
    elif ICMP in pkt:
        info.proto = "ICMP"
    if Raw in pkt:
        info.payload = bytes(pkt[Raw].load)
    return info


def analyze(detector, info, now):
    """Runs every enabled detection layer on one packet and returns its alerts."""
    alerts = []

    def add(a):
        if a:
            alerts.append(a)

    if info.proto == "TCP" and info.dport is not None:
        if detector.layer_enabled("stealth"):
            add(detector.check_stealth_scan(info.src_ip, info.dport, info.flags, now))
        if info.is_syn and detector.layer_enabled("volumetric"):
            add(detector.check_port_scan(info.src_ip, info.dport, now))
            add(detector.check_syn_flood(info.src_ip, now))
        if detector.layer_enabled("suspicious_port"):
            add(detector.check_suspicious_port(info.src_ip, info.dport, now))
        if info.payload and detector.layer_enabled("dpi"):
            add(detector.check_dpi_payload(info.src_ip, info.dport, info.payload, now))
    elif info.proto == "ICMP" and detector.layer_enabled("volumetric"):
        add(detector.check_icmp_flood(info.src_ip, now))
    elif info.proto == "UDP" and detector.layer_enabled("volumetric"):
        add(detector.check_udp_flood(info.src_ip, now))

    # Baseline-drift alarms raised while the rate detectors updated their baselines.
    alerts.extend(detector.drain_alerts())

    # Machine Learning Anomaly Detection. By default it is a fallback that
    # only sees packets no rule fired on; "ml_independent" scores every packet.
    if detector.layer_enabled("ml") and (not alerts or detector.engine_settings()["ml_independent"]):
        add(detector.check_ml_anomaly(
            info.src_ip, info.dst_ip, info.proto, info.length, now,
            flags=info.flags if info.proto == "TCP" else None, dport=info.dport,
        ))

    for a in alerts:
        a["timestamp"] = now
        a["src_ip"] = info.src_ip
        a["dst_ip"] = info.dst_ip
        a["protocol"] = info.proto
    return alerts
