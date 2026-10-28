import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from baselines import BoundedEMA, MADTracker, ThresholdParams
from detector import DetectionEngine
from experiments.poisoning_bound import METHODS, PARAMS, simulate

SYN = "SYN_FLOOD"


def _engine(**th):
    th_cfg = {"method": "drift_bounded", "update": "window", "population_prior": True, "cold_start": "static"}
    th_cfg.update(th)
    return DetectionEngine(offline=True, overrides={
        "engine": {"alert_cooldown": 0},
        "dynamic": {"adaptive_thresholds": th_cfg},
    })


def test_white_box_attack_respects_linear_bound():
    _, ema = simulate("ema", METHODS["ema"])
    _, bounded = simulate("drift_bounded", METHODS["drift_bounded"])
    _, rollback = simulate("drift_bounded_rollback", METHODS["drift_bounded_rollback"])

    assert ema["windows_to_ceiling"] is not None and ema["windows_to_ceiling"] < 20
    assert bounded["bound_violations"] == 0
    # The bound allows T0 + n(1+k)delta = 10 + 0.8n, so >= 112 windows to reach 100.
    assert bounded["windows_to_ceiling"] >= (PARAMS.ceiling - bounded["t0"]) / ((1 + PARAMS.k_sigma) * PARAMS.max_rise)
    assert bounded["first_drift_alarm"] is not None and bounded["first_drift_alarm"] < 40
    assert rollback["windows_to_ceiling"] is None
    assert rollback["threshold_at_300"] < PARAMS.static


def test_bounded_ema_caps_first_sample_and_rise():
    p = ThresholdParams(k_sigma=3, floor=10, ceiling=100, static=40, warmup=5, max_rise=0.5)
    e = BoundedEMA(alpha=0.1)
    e.update(500, p.static, p.max_rise)
    assert e.mean == 40  # a fresh baseline can't start above the static threshold
    before = e.threshold(p)
    e.update(1000, p.static, p.max_rise)
    assert e.threshold(p) - before <= (1 + p.k_sigma) * p.max_rise + 1e-9


def test_mad_tracker_ignores_single_outlier():
    p = ThresholdParams(k_sigma=3, floor=1, ceiling=1000, static=40, warmup=5, max_rise=0.5)
    t = MADTracker(history=50)
    for v in [5, 6, 5, 4, 5, 6, 5, 4] * 5:
        t.observe(v, p)
    before = t.threshold(p)
    t.observe(900, p)
    # Bounded influence: the threshold may move a step with tied data, never towards 900.
    assert t.threshold(p) < before + 3


def test_window_mode_updates_once_per_window_with_peak():
    e = _engine()
    src = "192.0.2.10"
    for i in range(12):                 # 12 SYNs inside window [1000, 1005)
        e.check_syn_flood(src, 1000.0 + i * 0.1)
    assert e.baselines.get_tracker(src, SYN, 1001.5).samples == 0  # window still open
    e.check_syn_flood(src, 1006.0)       # first packet of the next window closes it
    tracker = e.baselines.get_tracker(src, SYN, 1006.0)
    assert tracker.samples == 1
    assert tracker.mean == 12            # the peak sliding count, not 1 or the packet count
    e.stop()


def test_alerted_windows_are_not_learned():
    e = _engine()
    src = "192.0.2.11"
    for i in range(60):                  # 60 SYNs in one window: above the static 40
        e.check_syn_flood(src, 2000.0 + i * 0.05)
    e.check_syn_flood(src, 2006.0)
    assert e.baselines.get_tracker(src, SYN, 2006.0).samples == 0
    e.stop()


def test_cold_start_static_vs_legacy_ceiling():
    legacy = _engine(method="ema", update="packet", population_prior=False, cold_start="ceiling")
    improved = _engine()
    assert legacy._get_adaptive_threshold("198.51.100.1", SYN, 0, 40, 0.0)[0] == 100
    assert improved._get_adaptive_threshold("198.51.100.1", SYN, 0, 40, 0.0)[0] == 40
    legacy.stop()
    improved.stop()


def test_population_prior_seeds_new_sources():
    e = _engine()
    for i in range(60):                  # benign windows from many hosts warm the population
        e.update_baseline_if_normal(f"10.1.0.{i % 20}", SYN, 5, False, 100.0 + i)
    pop = e.baselines.population(SYN)
    assert pop.samples >= 50
    thresh, _ = e._get_adaptive_threshold("203.0.113.7", SYN, 0, 40, 200.0)
    assert thresh == 10                  # population threshold (5 + 3*0 -> floor), not 40 or 100
    e.stop()


def test_drift_alarm_raises_alert_and_rolls_back():
    e = _engine(drift={"rollback": True})
    src = "192.0.2.50"
    now = 0.0
    for _ in range(60):                  # benign history so the reference is warm
        now += 5
        e.update_baseline_if_normal(src, SYN, 5, False, now)
    tracker = e.baselines.get_tracker(src, SYN, now)
    alerts = []
    for _ in range(80):                  # white-box ramp just below the current threshold
        now += 5
        p = e._threshold_params(SYN, 40)
        e.update_baseline_if_normal(src, SYN, tracker.threshold(p) * 0.98, False, now)
        alerts += e.drain_alerts()
    assert alerts, "drift alarm never fired"
    assert all(a["layer"] == "drift" for a in alerts)
    assert "rolled back" in alerts[0]["description"]
    assert tracker.threshold(e._threshold_params(SYN, 40)) < 40
    e.stop()
