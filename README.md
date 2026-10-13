# Network Intrusion Detection System (NIDS)

A modern, multi-layered Intrusion Detection System built with **Python, Scapy, Flask, and Scikit-Learn**. It captures live network traffic and analyzes it using three distinct, enterprise-grade detection layers to identify both known exploits and zero-day anomalies.

## Core Features

1. **Rule-Based Threat Intelligence (DPI):** 
   - Dynamically loads signatures from an external `rules.json` file—matching industry standards for decoupled threat intelligence.
   - Performs Deep Packet Inspection (L7) using precompiled Regex signatures to catch application-layer exploits like SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, and Malware C2 beacons.
   - **Hot-Reloadable Rules:** Edit `rules.json` and the engine automatically reloads and compiles new signatures without restarting the capture thread.
2. **Adaptive Volumetric & State Analysis:** 
   - Uses **Adaptive Thresholds** based on Exponential Moving Average (EMA) and Mean Absolute Deviation to catch brute-force attacks (SYN Floods, ICMP Floods, UDP Floods, and Port Scans). Static thresholds act as fallbacks.
   - Thresholds adapt to legitimate traffic patterns while resisting slow-ramp "poisoning" attacks through configured floor/ceiling limits.
   - Inspects raw TCP headers for illegal flag combinations to detect stealth reconnaissance (NULL, XMAS, and FIN scans).
3. **Continuous Machine Learning Anomaly Engine:** 
   - Utilizes Scikit-Learn's `IsolationForest` to learn your network's unique baseline automatically.
   - Continuously retrains in the background on recent clean traffic to adapt to changing network conditions.
   - Considers packet lengths, protocols, inter-arrival times (IAT), TCP flags, and per-IP packet rates.
4. **Dynamic Reputation & Auto-Response:**
   - Tracks per-IP risk scores that decay over time.
   - Automatically issues temporary blocks (via iptables or a dry-run logger) for IPs that exceed the score threshold.
   - Supports configurable IP allowlists (e.g. `127.0.0.1`) that can never be blocked.

Includes a safe local traffic generator (`demo.py`) so you can trigger every alert on demand to test the system without requiring actual malware.

## Architecture

- **`app.py`**: Flask server and JSON API (runs on port 5001). Provides the real-time web dashboard.
- **`sniffer.py`**: Background packet capture engine utilizing Scapy's AsyncSniffer.
- **`detector.py`**: The core detection engine integrating ML Analysis, Adaptive Thresholds, Reputation scoring, and DPI.
- **`rules_loader.py` & `baselines.py`**: Handle hot-reloading signatures and managing Exponential Moving Average thresholds.
- **`model.py` & `reputation.py`**: Manage continuous Isolation Forest retraining and IP risk scoring with pluggable blocking (iptables).
- **`rules.json`**: The decoupled Threat Intelligence database containing malware signatures, suspicious ports, and dynamic configurations.
- **`database.py`**: SQLite storage for persisting alerts.
- **`demo.py`**: Safe local traffic generator with continuous simulation capabilities.

## Installation & Usage (macOS / Linux)

### 1. Install Dependencies

You will need `scikit-learn` and `numpy` installed for the root user, as the raw socket sniffer requires root privileges (`sudo`).

```bash
sudo pip install -r requirements.txt scikit-learn numpy
```

### 2. Start the NIDS Server

Open a terminal and launch the background engine and web server:

```bash
sudo python app.py
```
Open **http://127.0.0.1:5001** in your browser and click **Start Monitoring**. Allow the system a few seconds to ingest the first batch of packets to begin adaptive thresholding and ML baseline training.

### 3. Launch Test Attacks

Open a second terminal and use the provided simulation script to generate safe, local traffic that triggers the rules.

**Run individual attacks:**
```bash
sudo python3 demo.py portscan
sudo python3 demo.py synflood
sudo python3 demo.py icmpflood
sudo python3 demo.py udpflood
sudo python3 demo.py stealthscan
sudo python3 demo.py dpi
sudo python3 demo.py anomaly
```

**Run an automated continuous attack loop:**
```bash
sudo python3 demo.py continuous --interval 15
```
This will run in the background, routinely firing off every type of attack on a 15-second interval so you can monitor the dashboard reacting in real-time.

## Dynamic Configuration & Signatures

The `rules.json` file controls the entire detection engine at runtime without requiring a restart.

- **Threat Signatures:** Add new patterns (regex supported), set severity, and enable/disable individual rules instantly.
- **Adaptive Thresholds (`k_sigma`):** Adjust sensitivity. Bounded by `floor_limits` and `ceiling_limits` to prevent baseline poisoning.
- **Machine Learning:** Configure the `retrain_interval_seconds` and `window_size` to control how fast the Isolation Forest adapts.
- **Reputation & Blocking:** Set `block_ttl_seconds`, edit the CIDR `allowlist`, and toggle `dry_run` off to enable live iptables blocking.
