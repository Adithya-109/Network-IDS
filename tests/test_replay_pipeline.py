import sys
import os
import json
import threading
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
import replay
import evaluate
import summarize
from detector import DetectionEngine
from experiments.make_synthetic import generate

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIGS = os.path.join(ROOT, "experiments", "configs")


@pytest.fixture(scope="module")
def scenario(tmp_path_factory):
    out = tmp_path_factory.mktemp("synthetic")
    pcap, labels, _ = generate(str(out), seed=7, warmup=30.0, duration=340.0)
    return pcap, labels


def test_offline_engine_starts_no_threads():
    before = threading.active_count()
    engine = DetectionEngine(offline=True)
    assert threading.active_count() == before
    assert not engine.ml_engine.is_trained  # model.joblib is never loaded offline
    engine.stop()


def test_overrides_reach_engine_settings():
    engine = DetectionEngine(offline=True, overrides={
        "engine": {"alert_cooldown": 0, "layers": {"dpi": False}},
        "dynamic": {"adaptive_thresholds": {"k_sigma": 5.0}},
    })
    assert engine.engine_settings()["alert_cooldown"] == 0
    assert not engine.layer_enabled("dpi")
    assert engine.layer_enabled("volumetric")
    th = engine._get_dynamic_config()["adaptive_thresholds"]
    assert th["k_sigma"] == 5.0
    assert th["floor_limits"]["SYN_FLOOD"] == 10  # untouched keys survive the merge
    engine.stop()


def test_replay_is_deterministic_and_does_not_persist(scenario, tmp_path):
    pcap, _ = scenario
    model_path = os.path.join(ROOT, "model.joblib")
    model_mtime = os.path.getmtime(model_path) if os.path.exists(model_path) else None
    exp = replay.load_experiment(os.path.join(CONFIGS, "full.json"))

    # Enough packets to cross the 60s retraining interval, so the ML model is
    # trained mid-replay and its predictions are part of what must repeat.
    a = replay.run([pcap], exp, str(tmp_path / "a"), limit=8000, progress_every=0)
    b = replay.run([pcap], exp, str(tmp_path / "b"), limit=8000, progress_every=0)

    alerts_a = (tmp_path / "a" / "alerts.jsonl").read_text()
    alerts_b = (tmp_path / "b" / "alerts.jsonl").read_text()
    assert alerts_a == alerts_b
    assert (tmp_path / "a" / "traffic.csv").read_text() == (tmp_path / "b" / "traffic.csv").read_text()
    assert a["packets"] == 8000
    assert a["inputs"][0]["sha256"] == b["inputs"][0]["sha256"]
    assert a["seed"] == 42

    new_mtime = os.path.getmtime(model_path) if os.path.exists(model_path) else None
    assert new_mtime == model_mtime


def test_replay_detects_synthetic_attacks(scenario, tmp_path):
    pcap, labels = scenario
    exp = replay.load_experiment(os.path.join(CONFIGS, "no_ml.json"))
    run_dir = str(tmp_path / "no_ml")
    replay.run([pcap], exp, run_dir, progress_every=0)

    m = evaluate.evaluate(run_dir, labels, window=1)
    assert m["episode_level"]["detection_rate"] == 1.0
    assert m["window_level"]["recall"] == 1.0
    # Tight per-host adaptive thresholds trade a few false positives on bursty
    # benign hosts for poisoning resistance; keep that cost bounded.
    assert m["per_layer"]["volumetric"]["fpr"] < 0.01
    assert m["per_layer"]["stealth"]["precision"] == 1.0
    # The benign SSH session is the expected source of suspicious-port false positives.
    assert m["per_layer"]["suspicious_port"]["tp"] == 0


def _write_run(run_dir, traffic, alerts):
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "traffic.csv"), "w") as f:
        f.write("second,src_ip,packets\n")
        for sec, src, n in traffic:
            f.write(f"{sec},{src},{n}\n")
    with open(os.path.join(run_dir, "alerts.jsonl"), "w") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")


def test_evaluate_window_and_episode_metrics(tmp_path):
    run_dir = str(tmp_path / "run")
    traffic = [(100 + s, "10.0.0.5", 3) for s in range(10)]     # attacker, seconds 100-109
    traffic += [(100 + s, "10.0.0.9", 1) for s in range(10)]    # benign host
    alerts = [
        {"timestamp": 102.5, "src_ip": "10.0.0.5", "detection_type": "Port Scan", "layer": "volumetric"},
        {"timestamp": 106.1, "src_ip": "10.0.0.9", "detection_type": "Suspicious Port Activity", "layer": "suspicious_port"},
    ]
    _write_run(run_dir, traffic, alerts)
    labels = tmp_path / "labels.csv"
    # CIDR source and an ISO timestamp (1970-01-01T00:01:42Z == 102).
    labels.write_text("label,src_ip,start,end\nportscan,10.0.0.0/30,101,103.5\n"
                      "portscan,10.0.0.4/30,1970-01-01T00:01:42+00:00,103.5\n")

    m = evaluate.evaluate(run_dir, str(labels), window=1)
    wl = m["window_level"]
    # Attack units for 10.0.0.5 (in 10.0.0.4/30): seconds 102 and 103 -> one hit, one miss.
    assert (wl["tp"], wl["fn"], wl["fp"]) == (1, 1, 1)
    assert wl["tn"] == 20 - 3
    assert m["per_layer"]["volumetric"]["fp"] == 0
    assert m["per_layer"]["suspicious_port"]["fp"] == 1
    eps = m["episode_level"]
    assert eps["detected"] == 1  # the 10.0.0.0/30 episode never matches 10.0.0.5
    assert eps["episodes"][1]["time_to_detect"] == pytest.approx(0.5)

    # A 5s window merges seconds 100-104 into one attack unit for 10.0.0.5.
    m5 = evaluate.evaluate(run_dir, str(labels), window=5)
    assert m5["units"] == 4
    assert m5["window_level"]["tp"] == 1 and m5["window_level"]["fn"] == 0


def test_summarize_groups_seeds(tmp_path):
    dirs = []
    for seed, recall in [(1, 0.8), (2, 1.0)]:
        d = tmp_path / f"r{seed}"
        d.mkdir()
        (d / "run.json").write_text(json.dumps({"experiment": {"name": "x"}, "seed": seed, "throughput_pps": 100.0}))
        (d / "metrics.json").write_text(json.dumps({
            "window_level": {"precision": 1.0, "recall": recall, "f1": None, "fpr": 0.0},
            "episode_level": {"detection_rate": 1.0, "median_time_to_detect": 0.5},
        }))
        dirs.append(str(d))
    (row,) = summarize.summarize(dirs)
    assert row["runs"] == 2 and row["seeds"] == [1, 2]
    assert row["recall"] == pytest.approx(0.9)
    assert row["recall_ci95"] > 0
    assert row["f1"] is None
