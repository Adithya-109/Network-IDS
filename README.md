# Network Intrusion Detection System (NIDS)

A modern, multi-layered Intrusion Detection System built with **Python, Scapy, Flask, and Scikit-Learn**. It captures live network traffic and analyzes it using three distinct, enterprise-grade detection layers to identify both known exploits and zero-day anomalies.

## Core Features

1. **Rule-Based Threat Intelligence (DPI):** 
   - Dynamically loads signatures from an external `rules.json` file—matching industry standards for decoupled threat intelligence.
   - Performs Deep Packet Inspection (L7) using precompiled Regex signatures to catch application-layer exploits like SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal, and Malware C2 beacons.
   - **Hot-Reloadable Rules:** Edit `rules.json` and the engine automatically reloads and compiles new signatures without restarting the capture thread.
2. **Adaptive Volumetric & State Analysis:** 
   - Uses **Adaptive Thresholds** (threshold = baseline mean + k·σ, clamped to floor/ceiling limits) to catch brute-force attacks (SYN Floods, ICMP Floods, UDP Floods, and Port Scans). Static thresholds act as the fallback for sources that have no baseline yet.
   - **Poisoning-resilient baselines** (see "Adaptive Thresholds & Poisoning Resistance" below): one baseline sample per closed time window, never learned from windows that alerted; a population prior for new source IPs; and a drift-bounded tracker whose threshold can only rise linearly, with a slow reference baseline that raises a *Baseline Drift* alert and rolls the baseline back when it is being walked upwards.
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
- **`pipeline.py`**: Per-packet parsing and layer dispatch, shared by live capture and offline replay.
- **`detector.py`**: The core detection engine integrating ML Analysis, Adaptive Thresholds, Reputation scoring, and DPI.
- **`rules_loader.py` & `baselines.py`**: Handle hot-reloading signatures and managing Exponential Moving Average thresholds.
- **`model.py` & `reputation.py`**: Manage continuous Isolation Forest retraining and IP risk scoring with pluggable blocking (iptables).
- **`rules.json`**: The decoupled Threat Intelligence database containing malware signatures, suspicious ports, and dynamic configurations.
- **`database.py`**: SQLite storage for persisting alerts.
- **`demo.py`**: Safe local traffic generator with continuous simulation capabilities.
- **`replay.py`, `evaluate.py`, `summarize.py`, `experiments/`**: Offline PCAP replay and evaluation harness (see below).

## Installation & Usage (macOS / Linux)

### 1. Install Dependencies

Dependencies are pinned in `requirements.txt` (tested on Python 3.13). Install them into a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. Start the NIDS Server

Open a terminal and launch the background engine and web server:

```bash
sudo .venv/bin/python app.py
```
Live capture listens on `lo0` by default so `demo.py` traffic is seen. Set `NIDS_IFACE` to monitor another interface, e.g. `sudo NIDS_IFACE=en0 .venv/bin/python app.py`.
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

## Adaptive Thresholds & Poisoning Resistance

Configured under `dynamic.adaptive_thresholds` in `rules.json`:

| Key | Values | Meaning |
|---|---|---|
| `method` | `drift_bounded` (default), `ema`, `mad` | Baseline tracker. `ema` is the original gated EMA; `mad` uses median + k·1.4826·MAD over the last `mad.history` windows. |
| `update` | `window` (default), `packet` | `window`: one sample per closed tumbling window (its peak sliding count), skipped if the window alerted. `packet` is the original per-packet update. |
| `population_prior` | `true` / `false` | New sources start from a copy of the population baseline learned from all hosts. |
| `cold_start` | `static` / `ceiling` | Threshold for sources without a warm baseline: the operator's static threshold, or the ceiling (original behaviour). |
| `drift.max_rise_frac` | default `0.02` | Max upward move of mean and σ per sample, as a fraction of the metric's floor (δ). |
| `drift.ref_alpha` | default `0.01` | Learning rate of the long-term reference baseline (fast baseline uses `alpha`). |
| `drift.rollback` | `true` / `false` | On a drift alarm, reset the fast baseline to the reference. |

With `drift_bounded`, a threshold can rise by at most (1 + k)·δ per window, so after n windows T ≤ T₀ + n(1 + k)·δ, whatever the attacker sends. A plain EMA under the same white-box attacker reaches the ceiling in about 12 windows. Window counts replace packet counts in `warmup_samples` when `update` is `window`.

Hot-reloading `rules.json` picks up `k_sigma`, limits, `update`, `cold_start`, `max_rise_frac` and `rollback`; `method`, `alpha`, `ref_alpha`, `mad.history` and `population_prior` take effect on the next start.

### Poisoning experiments

```bash
# White-box attacker that always stays just below the threshold (numeric, no PCAP):
.venv/bin/python experiments/poisoning_bound.py --out results/poisoning_bound

# Blind slow-ramp + fresh-IP floods replayed as PCAPs, across growth rates and seeds:
.venv/bin/python experiments/run_poisoning.py --growth 0.02 0.05 0.10 --seeds 1 2 3

# One scenario by hand, with a per-sample threshold trace for plotting:
.venv/bin/python experiments/make_poisoning.py --out data/poison_g05 --growth 0.05
.venv/bin/python replay.py data/poison_g05/scenario.pcap --config experiments/configs/poisoning/p_drift_rollback.json \
    --out results/p_drift_rollback --trace-thresholds --trace-src 10.0.0.88
```

The configs in `experiments/configs/poisoning/` isolate the volumetric layer: `p_static`, `p_legacy` (original design), `p_window_ema` (window updates without the drift bound), `p_mad`, `p_drift` and `p_drift_rollback`. `experiments/configs/full_legacy.json` runs all layers with the original adaptive design, for comparison with `full.json`.

## Reproducible Experiments (offline PCAP replay)

`replay.py` runs capture files through the same detection pipeline as live mode, using packet timestamps as the clock. Offline runs need no root, start no background threads, never load or overwrite `model.joblib`, never block anything and never write to `nids.db`. The same PCAP, config and seed always produce the same alerts.

```bash
# 1. A small labelled synthetic scenario (benign hosts + 6 attack episodes)
.venv/bin/python experiments/make_synthetic.py --out data/synthetic --seed 1

# 2. Replay it under an experiment config
.venv/bin/python replay.py data/synthetic/scenario.pcap --config experiments/configs/full.json --out results/full

# 3. Score it against ground truth (window-level P/R/F1/FPR per layer, episode detection, time-to-detect)
.venv/bin/python evaluate.py results/full --labels data/synthetic/labels.csv --window 1

# 4. Aggregate runs: mean ± 95% CI per experiment (repeat a config with --seed N for CIs)
.venv/bin/python summarize.py results/*/ --csv results/summary.csv
```

- **Experiment configs** (`experiments/configs/*.json`) are deep-merged over `rules.json`. The `engine` section sets the alert cooldown, the ML layer's minimum packet rate, whether ML scores every packet (`ml_independent`) and which layers run. The shipped configs are `full`, `static_baseline`, `no_ml`, `ml_only` and `volumetric_only`.
- **Ground truth** is a CSV of attack episodes: `label,src_ip,start,end`, where `src_ip` may be a CIDR and times are epoch seconds or ISO 8601 with a UTC offset.
- **Run outputs**: `alerts.jsonl`, `traffic.csv` (packets per second per source, the evaluation's denominator), `run.json` (config, SHA-256 of the inputs and rules, package versions, git commit, wall time and throughput) and `metrics.json`.
- **Tests**: `.venv/bin/python -m pytest -q`
