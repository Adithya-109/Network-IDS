"""Background packet capture. Runs Scapy's AsyncSniffer on its own thread so
the Flask dashboard never blocks on packet capture. Exposes a small
thread-safe API (start/stop/get_stats) that app.py calls from request
handlers."""

import threading
import time
from collections import deque

import config
import database
from detector import DetectionEngine

# Imported lazily-ish at module load; Scapy prints a runtime warning on some
# systems if certain optional dependencies are missing, which is harmless.
from scapy.all import AsyncSniffer, get_if_list, conf
from pipeline import parse_packet, analyze

DASHBOARD_PORT = 5001


class SnifferService:
    def __init__(self):
        self._lock = threading.Lock()
        self._sniffer = None
        self._draining_sniffer = None
        self.detector = DetectionEngine()

        self.stats = {
            "running": False,
            "packet_count": 0,
            "web_count": 0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "other_count": 0,
            "start_time": None,
            "stop_time": None,
            "error": None,
        }
        # timestamps of recently seen packets, used to compute packets/sec
        self._recent_ts = deque(maxlen=20000)

    # -- packet handling ---------------------------------------------------

    def _handle_packet(self, pkt):
        now = time.time()

        with self._lock:
            self.stats["packet_count"] += 1
            self._recent_ts.append(now)

        info = parse_packet(pkt)
        if info is None:
            with self._lock:
                self.stats["other_count"] += 1
            return

        is_web = info.proto == "TCP" and DASHBOARD_PORT in (info.sport, info.dport)

        with self._lock:
            count_key = f"{info.proto.lower()}_count"
            if count_key in self.stats:
                self.stats[count_key] += 1
            else:
                self.stats["other_count"] += 1
            if is_web:
                self.stats["web_count"] += 1

        if is_web:
            # Skip analyzing the dashboard's own frontend-to-backend polling traffic
            # so the AI doesn't flag our own requests!
            return

        # Detection runs on the capture timestamp, the same clock replay.py uses.
        for a in analyze(self.detector, info, float(pkt.time)):
            database.insert_alert(a)

    # -- lifecycle -----------------------------------------------------

    def start(self):
        with self._lock:
            if self.stats["running"]:
                return False, "already running"

            # A prior stop() intentionally returned without waiting for the
            # old AsyncSniffer's per-interface capture threads to release
            # their Npcap handles (see stop()'s comment). If we open new
            # handles on the same interfaces while the old ones are still
            # closing, Npcap can split delivery of incoming packets between
            # the stale and the new reader, so the live detector silently
            # only sees a fraction of the traffic. Give the old threads a
            # bounded window to actually finish before reopening.
            if self._draining_sniffer is not None:
                try:
                    self._draining_sniffer.join(timeout=2)
                except Exception:
                    pass
                self._draining_sniffer = None

            if not (conf.use_pcap or getattr(conf, "use_bpf", False)):
                message = (
                    "No packet capture backend found (Npcap/libpcap/bpf is missing, or "
                    "this app is not running with Administrator/root privileges). "
                    "On Windows, install Npcap. On Mac/Linux, run with sudo."
                )
                self.stats["error"] = message
                return False, message

            try:
                ifaces = get_if_list()
            except Exception:
                ifaces = None

            self.stats.update(
                {
                    "packet_count": 0,
                    "web_count": 0,
                    "tcp_count": 0,
                    "udp_count": 0,
                    "icmp_count": 0,
                    "other_count": 0,
                    "start_time": time.time(),
                    "stop_time": None,
                    "error": None,
                }
            )
            self._recent_ts.clear()
            # Fresh detection state each session so sliding-window counters and
            # alert cooldowns from a previous run can't suppress or skew alerts
            # in this one (matters when re-running a demo shortly after restart).
            self.detector = DetectionEngine()

            try:
                self._sniffer = AsyncSniffer(
                    prn=self._handle_packet,
                    store=False,
                    iface=config.CAPTURE_IFACE,
                )
                self._sniffer.start()
            except Exception as exc:
                self.stats["error"] = str(exc)
                self.stats["running"] = False
                return False, str(exc)

            self.stats["running"] = True
            return True, "started"

    def stop(self):
        with self._lock:
            if not self.stats["running"] or not self._sniffer:
                return False, "not running"
            try:
                # join=False: on Windows, AsyncSniffer.stop() can block
                # indefinitely joining per-interface capture threads for
                # idle/virtual adapters (WAN miniports, Bluetooth PAN, etc.)
                # that never receive a packet. That join would happen while
                # holding self._lock, freezing every other endpoint (status,
                # stats, start) along with it. Signal the sniffer to stop and
                # return immediately instead of waiting for the threads to
                # fully unwind.
                self._sniffer.stop(join=False)
            except Exception:
                pass
            if self.detector:
                self.detector.stop()
            self._draining_sniffer = self._sniffer
            self._sniffer = None
            self.stats["running"] = False
            self.stats["stop_time"] = time.time()
            return True, "stopped"

    def get_stats(self):
        now = time.time()
        with self._lock:
            data = dict(self.stats)
            cutoff = now - 1.0
            pps = sum(1 for t in self._recent_ts if t >= cutoff)

        if not data["start_time"]:
            data["uptime"] = 0
        elif data["running"]:
            data["uptime"] = now - data["start_time"]
        else:
            # Stopped: freeze uptime at the moment stop() was called instead
            # of letting it keep counting up off the wall clock.
            data["uptime"] = (data["stop_time"] or now) - data["start_time"]

        # Packets/sec should read 0 once stopped rather than trailing off
        # over the last second of stale timestamps.
        data["pps"] = pps if data["running"] else 0
        return data


sniffer_service = SnifferService()
