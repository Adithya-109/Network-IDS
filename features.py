"""Per-window traffic features for the ML anomaly layer.

Packets are aggregated per source IP over tumbling windows aligned to a
global grid (floor(t / width) * width). Because every source shares the grid,
all open windows close together when packet time crosses a grid boundary,
which hands the model one batch to score instead of one call per packet.
"""

import math
from collections import Counter

import numpy as np

FEATURE_NAMES = [
    "log_packets", "log_bytes", "mean_size", "std_size",
    "log_dst_ips", "log_dst_ports", "dst_port_entropy", "low_port_frac",
    "tcp_frac", "udp_frac", "icmp_frac",
    "syn_ratio", "syn_only_ratio", "ack_ratio", "rst_ratio", "fin_ratio",
    "log_mean_iat", "log_std_iat",
]

_SYN, _ACK, _RST, _FIN = 0x02, 0x10, 0x04, 0x01


class _Acc:
    __slots__ = ("packets", "bytes", "size_sq", "dst_ips", "dst_ports", "low_ports",
                 "tcp", "udp", "icmp", "syn", "syn_only", "ack", "rst", "fin",
                 "last_ts", "iat_n", "iat_sum", "iat_sq")

    def __init__(self):
        self.packets = self.bytes = self.size_sq = 0
        self.dst_ips = set()
        self.dst_ports = Counter()
        self.low_ports = 0
        self.tcp = self.udp = self.icmp = 0
        self.syn = self.syn_only = self.ack = self.rst = self.fin = 0
        self.last_ts = None
        self.iat_n = 0
        self.iat_sum = self.iat_sq = 0.0

    def add(self, info, ts):
        self.packets += 1
        self.bytes += info.length
        self.size_sq += info.length * info.length
        self.dst_ips.add(info.dst_ip)
        if info.dport is not None:
            self.dst_ports[info.dport] += 1
            if info.dport < 1024:
                self.low_ports += 1
        if info.proto == "TCP":
            self.tcp += 1
            f = info.flags or 0
            self.syn += bool(f & _SYN)
            self.syn_only += bool(f & _SYN) and not (f & _ACK)
            self.ack += bool(f & _ACK)
            self.rst += bool(f & _RST)
            self.fin += bool(f & _FIN)
        elif info.proto == "UDP":
            self.udp += 1
        elif info.proto == "ICMP":
            self.icmp += 1
        if self.last_ts is not None:
            iat = max(ts - self.last_ts, 0.0)
            self.iat_n += 1
            self.iat_sum += iat
            self.iat_sq += iat * iat
        self.last_ts = ts

    def vector(self, width):
        n = self.packets
        mean_size = self.bytes / n
        std_size = math.sqrt(max(self.size_sq / n - mean_size ** 2, 0.0))
        ports = sum(self.dst_ports.values())
        entropy = 0.0
        for c in self.dst_ports.values():
            p = c / ports
            entropy -= p * math.log2(p)
        tcp = self.tcp or 1
        if self.iat_n:
            mean_iat = self.iat_sum / self.iat_n
            std_iat = math.sqrt(max(self.iat_sq / self.iat_n - mean_iat ** 2, 0.0))
        else:
            mean_iat, std_iat = width, 0.0  # a single packet: no gap observed within the window
        return [
            math.log1p(n), math.log1p(self.bytes), mean_size, std_size,
            math.log1p(len(self.dst_ips)), math.log1p(len(self.dst_ports)), entropy,
            self.low_ports / ports if ports else 0.0,
            self.tcp / n, self.udp / n, self.icmp / n,
            self.syn / tcp, self.syn_only / tcp, self.ack / tcp, self.rst / tcp, self.fin / tcp,
            math.log10(mean_iat + 1e-6), math.log10(std_iat + 1e-6),
        ]


class WindowAggregator:
    """Accumulates per-source features and closes every window at grid boundaries."""

    def __init__(self, width=5.0):
        self.width = width
        self.current = None  # start of the open grid window
        self.open = {}       # src_ip -> _Acc

    def add(self, info, ts):
        """Adds a packet; returns the windows closed by it as (start, srcs, X, packet_counts)."""
        start = math.floor(ts / self.width) * self.width
        closed = None
        if self.current is not None and start > self.current:
            closed = self.close()
        if self.current is None or start > self.current:
            self.current = start
        acc = self.open.get(info.src_ip)
        if acc is None:
            acc = self.open[info.src_ip] = _Acc()
        acc.add(info, ts)
        return closed

    def close(self):
        """Closes every open window (also used at the end of a capture)."""
        if not self.open:
            return None
        srcs = list(self.open)
        X = np.array([self.open[s].vector(self.width) for s in srcs], dtype=float)
        counts = [self.open[s].packets for s in srcs]
        start = self.current
        self.open = {}
        return start, srcs, X, counts
