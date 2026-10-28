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
   - Scores one feature vector per source and 5 s window (volume, packet sizes, destination fan-out, port entropy, protocol mix, TCP flag ratios, inter-arrival times), all windows of a time step in one batch.
   - Retrains periodically on *clean* windows only (no recent rule alert or high reputation score for that source), kept as a uniform reservoir sample, and calibrates its alert threshold to a target false-positive rate.
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
| `std_floor` | `poisson` (default), `none` | Floors σ at √mean, as for Poisson counts, so perfectly regular traffic (σ = 0, e.g. a monitor probing the same 20 ports every window) is not alerted at its own mean. |
| `bootstrap_seconds` | default `0` (off) | Trusted training period from the first packet: baselines learn every window below the ceiling (even ones that alerted against a cold threshold) without the drift bound, so legitimately busy hosts get their own baselines. Assumes the period is attack-free. `rules.json` ships with `0` so demo attacks fired in the first minutes are never learned; on a real network set it (e.g. `300`) to a period you trust. Without it, a busy host only ever meets thresholds it exceeds, alerts on every window and never adapts. |

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

```bash
# Heterogeneous hosts: busy benign hosts above the static thresholds plus quiet hosts attacked below them
.venv/bin/python experiments/run_heterogeneous.py --seeds 1 2 3
```

`evaluate.py --exclude-first 300` scores only traffic after a 300 s training period, and `metrics.json` lists false-positive windows per source (`false_positive_units_by_src`).

The configs in `experiments/configs/poisoning/` and `experiments/configs/heterogeneous/` isolate the volumetric layer: `p_static`, `p_legacy` (original design), `p_window_ema` (window updates without the drift bound), `p_mad`, `p_drift` and `p_drift_rollback`. `experiments/configs/full_legacy.json` runs all layers with the original adaptive design, for comparison with `full.json`.

## ML Anomaly Layer

Configured under `dynamic.model_learning` in `rules.json`:

| Key | Default | Meaning |
|---|---|---|
| `mode` | `window` | `window`: per-(source, window) features scored in batches (see `features.py`). `packet`: the original per-packet model (8 packet features, `contamination`). |
| `window_seconds` | `5` | Width of the ML windows (aligned to a global time grid). |
| `buffer` | `reservoir` | `reservoir`: uniform sample of all clean windows seen; `recent`: the last `window_size` windows. |
| `target_fpr` | `0.01` | Each retrain sets the alert threshold to the (1 − `target_fpr`) quantile of the new model's scores on a calibration reservoir of every rule-clean window, *including* ones the model flagged. Calibrating on the training buffer instead (which leaves flagged windows out) truncates the very tail the threshold sits in and more than doubles the false-positive rate. |
| `clean_training` | `true` | Only windows whose source raised no rule alert in the last `clean_horizon_seconds` (default 10) and whose reputation score is below `clean_max_reputation` (default 50) are learned. Longer exclusions turn every rule false positive into an under-represented host that the model then flags. |
| `min_train_windows` | `500` | No ML alerts or scores until the model was trained on this many windows (a model fitted on a handful of windows is mostly noise). |

Window-mode alerts are raised when a window closes (detection latency ≤ `window_seconds`) and carry the `window_start` and `anomaly_score` of the window they describe. On a quiet machine with one source (e.g. the loopback demo), reaching `min_train_windows` takes about 40 minutes; the live model is saved to `model_window.joblib` and reused across restarts.

```bash
# ML sweep: per-packet vs window ML and ablations, scenario with the attacks played twice
.venv/bin/python experiments/run_ml.py --seeds 1 2 3

# Score only the ML layer of any run; with scores.csv this adds ROC-AUC / PR-AUC
.venv/bin/python evaluate.py results/full --labels data/synthetic/labels.csv --window 5 --layers ml
```

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
- **Run outputs**: `alerts.jsonl`, `traffic.csv` (packets per second per source, the evaluation's denominator), `run.json` (config, SHA-256 of the inputs and rules, package versions, git commit, wall time and throughput), `scores.csv` (window-mode ML: every scored window's anomaly score and threshold) and `metrics.json`.
- **Tests**: `.venv/bin/python -m pytest -q`
