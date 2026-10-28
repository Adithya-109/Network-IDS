import sys
import os
import math
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
import pytest
from detector import DetectionEngine
from features import FEATURE_NAMES, WindowAggregator
from model import MLAnomalyEngine
from pipeline import PacketInfo

WINDOW_ML = {"mode": "window", "window_seconds": 5, "buffer": "reservoir", "target_fpr": 0.01,
             "clean_training": True, "clean_horizon_seconds": 10, "min_train_windows": 0}


def _syn(src, dport, dst="10.0.0.1"):
    return PacketInfo(src_ip=src, dst_ip=dst, proto="TCP", length=60, sport=40000, dport=dport, flags=0x02)


def test_aggregator_closes_every_source_at_the_grid_boundary():
    agg = WindowAggregator(width=5)
    assert agg.add(_syn("10.0.0.5", 22), 100.0) is None
    assert agg.add(_syn("10.0.0.5", 23), 101.0) is None
    assert agg.add(_syn("10.0.0.5", 24), 102.0) is None
    assert agg.add(_syn("10.0.0.9", 80), 103.0) is None
    start, srcs, X, counts = agg.add(_syn("10.0.0.9", 80), 105.5)  # crosses into [105, 110)
    assert start == 100 and srcs == ["10.0.0.5", "10.0.0.9"] and counts == [3, 1]
    assert X.shape == (2, len(FEATURE_NAMES))
    f = dict(zip(FEATURE_NAMES, X[0]))
    assert f["log_packets"] == pytest.approx(math.log1p(3))
    assert f["log_dst_ports"] == pytest.approx(math.log1p(3))
    assert f["dst_port_entropy"] == pytest.approx(math.log2(3))
    assert f["syn_only_ratio"] == 1.0 and f["tcp_frac"] == 1.0
    assert f["log_mean_iat"] == pytest.approx(math.log10(1.0 + 1e-6))
    # The packet that closed the window opened the next one.
    assert agg.close()[1] == ["10.0.0.9"]


def test_reservoir_buffer_is_bounded_deterministic_and_keeps_old_samples():
    def fill():
        e = MLAnomalyEngine(window_size=100, buffer="reservoir", persist=False, background=False, seed=3)
        for i in range(10000):
            e.add_clean_sample([float(i)])
        return [x[0] for x in e.training_buffer]
    a, b = fill(), fill()
    assert len(a) == 100 and a == b
    assert min(a) < 2000  # a recent-only buffer would hold just 9900-9999


def test_calibrated_threshold_hits_target_fpr():
    rng = np.random.default_rng(0)
    e = MLAnomalyEngine(window_size=4000, buffer="reservoir", target_fpr=0.02,
                        persist=False, background=False, seed=1)
    for x in rng.normal(size=(4000, 4)):
        e.add_clean_sample(x.tolist())
    assert e.retrain_once()
    assert e.trained_on == 4000
    fresh = e.score_batch(rng.normal(size=(5000, 4)))
    assert 0.005 < float(np.mean(fresh > e.threshold)) < 0.05
    outliers = e.score_batch(rng.normal(loc=6.0, size=(50, 4)))
    assert float(np.mean(outliers > e.threshold)) > 0.9


def _window_engine(**ml):
    cfg = dict(WINDOW_ML)
    cfg.update(ml)
    return DetectionEngine(offline=True, overrides={
        "engine": {"alert_cooldown": 0},
        "dynamic": {"model_learning": cfg, "adaptive_thresholds": {"bootstrap_seconds": 0}},
    })


def test_windows_after_rule_alerts_do_not_train_the_model():
    e = _window_engine()
    e._process_alert("10.0.0.66", "Port Scan", "High", "test", 100.0, layer="volumetric")
    e.observe_ml(_syn("10.0.0.66", 22), 101.0)
    e.observe_ml(_syn("10.0.0.10", 80), 101.5)
    e.observe_ml(_syn("10.0.0.10", 80), 106.0)  # closes [100, 105)
    assert len(e.ml_engine.training_buffer) == 1  # only the clean host's window
    e.stop()

    unclean = _window_engine(clean_training=False)
    unclean._process_alert("10.0.0.66", "Port Scan", "High", "test", 100.0, layer="volumetric")
    unclean.observe_ml(_syn("10.0.0.66", 22), 101.0)
    unclean.observe_ml(_syn("10.0.0.10", 80), 101.5)
    unclean.observe_ml(_syn("10.0.0.10", 80), 106.0)
    assert len(unclean.ml_engine.training_buffer) == 2
    unclean.stop()


def test_model_needs_min_train_windows_before_scoring():
    e = _window_engine(min_train_windows=10_000)
    rows = []
    e.score_sink = rows.append
    for x in np.random.default_rng(1).normal(size=(300, len(FEATURE_NAMES))):
        e.ml_engine.add_clean_sample(x.tolist())
    assert e.ml_engine.retrain_once()
    e.observe_ml(_syn("10.0.0.10", 80), 200.0)
    e.observe_ml(_syn("10.0.0.10", 80), 206.0)
    assert rows == []  # trained on 240 < 10000 windows: no scores, no alerts
    e.stop()


def test_window_alerts_describe_their_window_and_source():
    e = _window_engine()
    rng = np.random.default_rng(2)
    benign = []
    for i in range(400):  # quiet hosts: a few SYNs to port 80 per window
        agg = WindowAggregator(5)
        for j in range(3):
            agg.add(_syn("10.0.0.10", 80), i * 5 + j)
        benign.append(agg.close()[2][0] + rng.normal(scale=0.01, size=len(FEATURE_NAMES)))
    for x in benign:
        e.ml_engine.add_clean_sample(x.tolist())
    assert e.ml_engine.retrain_once()
    for p in range(200):  # one window: a scan of 200 ports
        e.observe_ml(_syn("10.0.0.66", 1000 + p, dst=f"10.0.1.{p % 50}"), 3000.0 + p * 0.02)
    alerts = e.observe_ml(_syn("10.0.0.10", 80), 3006.0)
    assert [a["src_ip"] for a in alerts] == ["10.0.0.66"]
    assert alerts[0]["window_start"] == 3000 and alerts[0]["layer"] == "ml"
    assert alerts[0]["anomaly_score"] > e.ml_engine.threshold
    # The flagged (but rule-clean) window calibrates the threshold, never trains the model.
    assert len(e.ml_engine.training_buffer) == 400
    assert len(e.ml_engine.calibration_buffer) == 1
    e.stop()
