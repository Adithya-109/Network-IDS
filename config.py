# Detection thresholds and settings for the NIDS demo.
# Tuned so the bundled demo.py traffic generator reliably trips each rule
# within a few seconds, while staying high enough to avoid false positives
# from normal browsing traffic during a live demo.

import os

DB_PATH = "nids.db"

# Interface for live capture. Defaults to loopback so demo.py traffic is seen;
# set NIDS_IFACE (e.g. en0, eth0) to monitor a real interface.
CAPTURE_IFACE = os.environ.get("NIDS_IFACE", "lo0")

# Port scan: N distinct destination ports from the same source IP within WINDOW seconds
PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 5

# SYN flood: N TCP SYN packets from the same source IP within WINDOW seconds
SYN_FLOOD_THRESHOLD = 40
SYN_FLOOD_WINDOW = 5

# ICMP flood: N ICMP echo requests from the same source IP within WINDOW seconds
ICMP_FLOOD_THRESHOLD = 30
ICMP_FLOOD_WINDOW = 5

# UDP flood: N UDP packets from the same source IP within WINDOW seconds
UDP_FLOOD_THRESHOLD = 50
UDP_FLOOD_WINDOW = 5

# Seconds to wait before re-alerting on the same (src_ip, detection_type) pair,
# so one sustained attack doesn't flood the alert table with duplicates.
ALERT_COOLDOWN = 8

# Traffic to these destination ports is flagged as "suspicious" (not an
# automatic confirmed attack) -- classic targets for recon / lateral movement.
SUSPICIOUS_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
}
