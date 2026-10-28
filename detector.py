import copy
import dataclasses
import logging
import math
from collections import defaultdict, deque

import config
from rules_loader import RulesLoader, deep_merge
from baselines import AdaptiveThresholds, LRUTTLCache, ThresholdParams, tracker_factory
from features import WindowAggregator
from model import MLAnomalyEngine
from reputation import ReputationManager

# Engine behaviour that experiments need to vary. Live defaults reproduce the
# original demo behaviour; override them under the "engine" key of rules.json
# or of an experiment config.
ENGINE_DEFAULTS = {
    # Seconds before re-alerting on the same (src_ip, detection) pair.
    "alert_cooldown": config.ALERT_COOLDOWN,
    # False: the ML layer only sees packets no rule fired on (live default).
    # True: the ML layer scores every packet, so it can be evaluated on its own.
    "ml_independent": False,
    # Minimum per-second packet rate before an ML anomaly is reported.
    "ml_min_pps": 10,
    "layers": {
        "stealth": True,
        "volumetric": True,
        "suspicious_port": True,
        "dpi": True,
        "ml": True,
        "drift": True,
    },
}

# Rate-based (volumetric) detectors, all handled by DetectionEngine.check_rate.
RATE_METRICS = {
    "PORT_SCAN": {
        "name": "Port Scan", "severity": "High", "distinct": True,
        "window": config.PORT_SCAN_WINDOW, "static": config.PORT_SCAN_THRESHOLD,
        "desc": "{src} contacted {val} distinct ports within {window}s (threshold: {thresh:.1f})",
    },
    "SYN_FLOOD": {
        "name": "SYN Flood", "severity": "High", "distinct": False,
        "window": config.SYN_FLOOD_WINDOW, "static": config.SYN_FLOOD_THRESHOLD,
        "desc": "{src} sent {val} TCP SYN packets within {window}s (threshold: {thresh:.1f})",
    },
    "ICMP_FLOOD": {
        "name": "ICMP Flood", "severity": "Medium", "distinct": False,
        "window": config.ICMP_FLOOD_WINDOW, "static": config.ICMP_FLOOD_THRESHOLD,
        "desc": "{src} sent {val} ICMP echo requests within {window}s (threshold: {thresh:.1f})",
    },
    "UDP_FLOOD": {
        "name": "UDP Flood", "severity": "Medium", "distinct": False,
        "window": config.UDP_FLOOD_WINDOW, "static": config.UDP_FLOOD_THRESHOLD,
        "desc": "{src} sent {val} UDP packets within {window}s (threshold: {thresh:.1f})",
    },
}


class _Window:
    """One tumbling baseline window of a (source, metric) pair.

    Its sample is the peak sliding-window value seen during the window, i.e.
    the same statistic the detector compares with the threshold."""
    __slots__ = ("start", "peak", "alerted")

    def __init__(self, start):
        self.start = start
        self.peak = 0
        self.alerted = False


class DetectionEngine:
    def __init__(self, rules_path="rules.json", overrides=None, offline=False):
        # offline=True is used for PCAP replay: no background threads, no
        # model.joblib persistence and no real blocking, with every timer
        # driven by packet timestamps so a run is deterministic.
        self.offline = offline
        # Time buckets for rate calculations (simple 1-second buckets)
        self._last_bucket = defaultdict(int) # src_ip -> bucket_ts
        self._packet_count = defaultdict(int) # src_ip -> count_in_bucket
        
        # Keep basic structures for sliding windows (bounded to avoid memory leaks)
        self.port_scan_map = defaultdict(deque)
        self.syn_map = defaultdict(deque)
        self.icmp_map = defaultdict(deque)
        self.udp_map = defaultdict(deque)
        self._rate_maps = {
            "PORT_SCAN": self.port_scan_map,
            "SYN_FLOOD": self.syn_map,
            "ICMP_FLOOD": self.icmp_map,
            "UDP_FLOOD": self.udp_map,
        }
        # Open baseline windows per (src_ip, metric) when baselines update per window.
        self._windows = LRUTTLCache(maxsize=40000, ttl=600)
        # Alerts raised outside a check's return value (baseline drift), drained by the pipeline.
        self._pending = []
        # Optional callback receiving one dict per baseline sample (replay --trace-thresholds).
        self.trace = None
        # Time of the first baseline sample; starts the bootstrap (training) period.
        self._t0 = None
        
        self._last_alert = {}
        
        self.rules_loader = RulesLoader(rules_path=rules_path, overrides=overrides)
        if not offline:
            self.rules_loader.start()
        self._engine_cache = (None, None)
        
        # Load initial config to set up dynamic modules
        rules = self.rules_loader.get_rules()
        dyn_cfg = rules.get("dynamic", {})
        
        th_cfg = dyn_cfg.get("adaptive_thresholds", {})
        self.baselines = AdaptiveThresholds(
            factory=tracker_factory(th_cfg),
            population_prior=th_cfg.get("population_prior", False),
        )
        
        ml_cfg = dyn_cfg.get("model_learning", {})
        # "packet" (original): one Isolation Forest call per packet on packet
        # features. "window": features per (source, window), scored in one
        # batch per window, with a threshold calibrated to target_fpr.
        self.ml_mode = ml_cfg.get("mode", "packet")
        window_mode = self.ml_mode == "window"
        self.ml_aggregator = WindowAggregator(ml_cfg.get("window_seconds", 5.0)) if window_mode else None
        # Optional callback receiving one dict per scored ML window (replay writes scores.csv).
        self.score_sink = None
        # Last rule-based (non-ML) alert time per source, for clean ML training.
        self._last_rule_alert = {}
        self.ml_engine = MLAnomalyEngine(
            retrain_interval_seconds=ml_cfg.get("retrain_interval_seconds", 60),
            window_size=ml_cfg.get("window_size", 5000),
            contamination=ml_cfg.get("contamination", "auto"),
            persist=not offline,
            background=not offline,
            seed=ml_cfg.get("seed", 42),
            n_estimators=ml_cfg.get("n_estimators", 100),
            buffer=ml_cfg.get("buffer", "recent"),
            target_fpr=ml_cfg.get("target_fpr", 0.01) if window_mode else None,
            model_filename="model_window.joblib" if window_mode else "model.joblib",
        )
        self.ml_engine.start()
        
        rep_cfg = dyn_cfg.get("reputation", {})
        self.reputation = ReputationManager(
            block_ttl_seconds=rep_cfg.get("block_ttl_seconds", 300),
            dry_run=True if offline else rep_cfg.get("dry_run", True),
            allowlist=rep_cfg.get("allowlist", []),
            background=not offline,
        )

        self.last_seen = defaultdict(float)
        self.smoothed_iat = defaultdict(lambda: 1.0)
        
    def stop(self):
        self.rules_loader.stop()
        self.ml_engine.stop()
        self.reputation.stop()

    def _get_dynamic_config(self):
        rules = self.rules_loader.get_rules()
        return rules.get("dynamic", {})

    def _is_dynamic_enabled(self):
        return self._get_dynamic_config().get("enabled", False)

    def engine_settings(self):
        """ENGINE_DEFAULTS merged with the "engine" rules section (cached per rules reload)."""
        rules = self.rules_loader.get_rules()
        cached_rules, settings = self._engine_cache
        if cached_rules is not rules:
            settings = deep_merge(copy.deepcopy(ENGINE_DEFAULTS), rules.get("engine", {}))
            self._engine_cache = (rules, settings)
        return settings

    def layer_enabled(self, layer):
        return self.engine_settings()["layers"].get(layer, True)

    def _cooldown_ok(self, key, now):
        cooldown = self.engine_settings()["alert_cooldown"]
        last = self._last_alert.get(key)
        if last is None or now - last >= cooldown:
            self._last_alert[key] = now
            
            # Prune old _last_alert entries to prevent memory leak
            if len(self._last_alert) > 5000:
                keys_to_delete = [k for k, ts in self._last_alert.items() if now - ts > cooldown * 2]
                for k in keys_to_delete:
                    del self._last_alert[k]
                    
            return True
        return False

    @staticmethod
    def _trim(dq, now, window):
        while dq and now - dq[0][0] > window:
            dq.popleft()
        if len(dq) > 1000: # hard limit to prevent OOM
            while len(dq) > 1000:
                dq.popleft()

    @staticmethod
    def _trim_flat(dq, now, window):
        while dq and now - dq[0] > window:
            dq.popleft()
        if len(dq) > 1000: # hard limit
            while len(dq) > 1000:
                dq.popleft()
                
    def _threshold_cfg(self):
        return self._get_dynamic_config().get("adaptive_thresholds", {})

    def _threshold_params(self, metric_name, fallback_static):
        th_cfg = self._threshold_cfg()
        floor = th_cfg.get("floor_limits", {}).get(metric_name, fallback_static // 2)
        return ThresholdParams(
            k_sigma=th_cfg.get("k_sigma", 3.0),
            floor=floor,
            ceiling=th_cfg.get("ceiling_limits", {}).get(metric_name, fallback_static * 2),
            static=fallback_static,
            warmup=th_cfg.get("warmup_samples", 50),
            max_rise=th_cfg.get("drift", {}).get("max_rise_frac", 0.02) * floor,
            poisson_std=th_cfg.get("std_floor", "none") == "poisson",
        )

    def _get_adaptive_threshold(self, src_ip, metric_name, current_val, fallback_static, now=None):
        if not self._is_dynamic_enabled():
            return fallback_static, False
        p = self._threshold_params(metric_name, fallback_static)
        tracker = self.baselines.get_tracker(src_ip, metric_name, now, p.warmup)
        if tracker.samples >= p.warmup:
            return tracker.threshold(p), True
        # Cold source. "ceiling" is the original behaviour (least sensitive);
        # "static" falls back to the operator's fixed threshold instead.
        if self._threshold_cfg().get("cold_start", "ceiling") == "ceiling":
            return p.ceiling, True
        return p.clamp(p.static), True
        
    def in_bootstrap(self, now):
        """True during the trusted training period (adaptive_thresholds.bootstrap_seconds)."""
        bootstrap = self._threshold_cfg().get("bootstrap_seconds", 0)
        if not bootstrap or now is None:
            return False
        if self._t0 is None:
            self._t0 = now
        return now - self._t0 < bootstrap

    def update_baseline_if_normal(self, src_ip, metric_name, current_val, is_alert, now=None):
        if not self._is_dynamic_enabled():
            return
        fallback = RATE_METRICS.get(metric_name, {}).get("static", current_val)
        p = self._threshold_params(metric_name, fallback)
        tracker = None
        if self.in_bootstrap(now):
            # Training period, assumed attack-free: learn every sample below
            # the ceiling, even ones that alerted against a cold threshold, so
            # legitimately busy hosts get their own baselines. No drift bound.
            is_alert = current_val >= p.ceiling
            if not is_alert:
                learn = dataclasses.replace(p, max_rise=math.inf, static=p.ceiling)
                tracker = self.baselines.update_baseline(src_ip, metric_name, current_val, now, learn, trusted=True)
        elif not is_alert:
            tracker = self.baselines.update_baseline(src_ip, metric_name, current_val, now, p)
        drifted = tracker is not None and hasattr(tracker, "drifted") and tracker.drifted(p)
        if self.trace is not None:
            self._trace_sample(src_ip, metric_name, current_val, not is_alert, now, p, drifted)
        if drifted:
            self._on_drift(src_ip, metric_name, tracker, p, now)

    def _on_drift(self, src_ip, metric_name, tracker, p, now):
        ref_thresh = tracker.reference_threshold(p)
        desc = (f"{src_ip} {RATE_METRICS.get(metric_name, {}).get('name', metric_name)} baseline mean "
                f"{tracker.mean:.1f} exceeds its long-term normal range (<= {ref_thresh:.1f}); "
                f"possible slow-ramp poisoning or real traffic change.")
        if self._threshold_cfg().get("drift", {}).get("rollback", False):
            tracker.rollback()
            desc += " Baseline rolled back."
        if self.layer_enabled("drift") and self._cooldown_ok((src_ip, f"DRIFT_{metric_name}"), now):
            self._pending.append(self._process_alert(
                src_ip, "Baseline Drift (Possible Poisoning)", "Medium", desc, now,
                baseline_info=f"mean={tracker.mean:.1f},ref_thresh={ref_thresh:.1f}",
                method="adaptive", layer="drift"))

    def _trace_sample(self, src_ip, metric_name, value, accepted, now, p, drifted):
        tracker = self.baselines.get_tracker(src_ip, metric_name, now, p.warmup)
        thresh, _ = self._get_adaptive_threshold(src_ip, metric_name, value, p.static, now)
        ref = tracker.reference_threshold(p) if hasattr(tracker, "reference_threshold") else None
        self.trace({
            "t": now, "src_ip": src_ip, "metric": metric_name, "value": value,
            "accepted": int(accepted), "samples": tracker.samples,
            "mean": tracker.mean, "std": tracker.std, "threshold": thresh,
            "ref_threshold": ref, "drifted": int(drifted),
        })

    def _observe_window(self, src_ip, metric_name, now, current_val, is_alert, width):
        """Per-window baseline updates: a closed window feeds the baseline once."""
        key = (src_ip, metric_name)
        start = math.floor(now / width) * width
        w = self._windows.get(key, now)
        if w is not None and w.start != start:
            self.update_baseline_if_normal(src_ip, metric_name, w.peak, w.alerted, now)
            w = None
        if w is None:
            w = _Window(start)
            self._windows.set(key, w, now)
        w.peak = max(w.peak, current_val)
        w.alerted = w.alerted or is_alert

    def drain_alerts(self):
        alerts, self._pending = self._pending, []
        return alerts

    def _process_alert(self, src_ip, detection_type, severity, description, now, baseline_info=None, method="static", rule_id=None, category=None, layer=None):
        if layer != "ml":
            self._last_rule_alert[src_ip] = now
            if len(self._last_rule_alert) > 50000:
                self._last_rule_alert = {k: t for k, t in self._last_rule_alert.items() if now - t < 3600}
        score, is_blocked = self.reputation.add_alert(src_ip, severity, detection_type, now)
        
        alert = {
            "detection_type": detection_type,
            "severity": severity,
            "description": description,
            "score": score,
            "method": method,
            "layer": layer,
        }
        
        if rule_id:
            alert["rule_id"] = rule_id
        if category:
            alert["category"] = category
        if baseline_info:
            alert["baseline"] = baseline_info
        if is_blocked:
            alert["action"] = "BLOCKED"
            
        return alert

    def check_rate(self, metric_name, src_ip, now, item=None):
        """Sliding-window rate check shared by the port-scan and flood detectors."""
        m = RATE_METRICS[metric_name]
        dq = self._rate_maps[metric_name][src_ip]
        if m["distinct"]:
            dq.append((now, item))
            self._trim(dq, now, m["window"])
            current_val = len({p for _, p in dq})
        else:
            dq.append(now)
            self._trim_flat(dq, now, m["window"])
            current_val = len(dq)

        thresh, is_dynamic = self._get_adaptive_threshold(src_ip, metric_name, current_val, m["static"], now)
        is_alert = current_val >= thresh

        # "packet" (original): every packet's sliding count updates the
        # baseline, so consecutive samples are near-identical. "window": one
        # update per closed tumbling window, skipped if that window alerted.
        if self._threshold_cfg().get("update", "packet") == "window":
            self._observe_window(src_ip, metric_name, now, current_val, is_alert, m["window"])
        else:
            self.update_baseline_if_normal(src_ip, metric_name, current_val, is_alert, now)

        if is_alert and self._cooldown_ok((src_ip, metric_name), now):
            desc = m["desc"].format(src=src_ip, val=current_val, window=m["window"], thresh=thresh)
            return self._process_alert(src_ip, m["name"], m["severity"], desc, now,
                                       layer="volumetric",
                                       baseline_info=f"thresh={thresh:.1f}",
                                       method="adaptive" if is_dynamic else "static")
        return None

    def check_port_scan(self, src_ip, dport, now):
        return self.check_rate("PORT_SCAN", src_ip, now, item=dport)

    def check_syn_flood(self, src_ip, now):
        return self.check_rate("SYN_FLOOD", src_ip, now)

    def check_icmp_flood(self, src_ip, now):
        return self.check_rate("ICMP_FLOOD", src_ip, now)

    def check_udp_flood(self, src_ip, now):
        return self.check_rate("UDP_FLOOD", src_ip, now)

    def check_stealth_scan(self, src_ip, dport, flags, now):
        scan_type = None
        if flags == 0:
            scan_type = "NULL Scan"
        elif flags == 0x29: # FIN | PSH | URG
            scan_type = "XMAS Scan"
        elif flags == 0x01: # FIN only
            scan_type = "FIN Scan"
            
        if scan_type:
            key = (src_ip, f"STEALTH_{scan_type}")
            if self._cooldown_ok(key, now):
                desc = f"{src_ip} sent a suspicious TCP packet with irregular flags ({scan_type}) to port {dport}."
                return self._process_alert(src_ip, f"TCP Stealth Scan ({scan_type})", "High", desc, now,
                                           method="static", layer="stealth")
        return None

    def check_suspicious_port(self, src_ip, dport, now):
        rules = self.rules_loader.get_rules()
        suspicious = rules.get("suspicious_ports", config.SUSPICIOUS_PORTS)
        
        if str(dport) in suspicious or dport in suspicious:
            key = (src_ip, f"SUSPICIOUS_PORT_{dport}")
            if self._cooldown_ok(key, now):
                service = suspicious.get(str(dport), suspicious.get(dport, "Unknown"))
                desc = f"{src_ip} accessed {service} port {dport} (often targeted by scanners)."
                return self._process_alert(src_ip, "Suspicious Port Activity", "Low", desc, now,
                                           method="static", layer="suspicious_port")
        return None

    def check_dpi_payload(self, src_ip, dport, payload, now):
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except Exception:
            return None
            
        rules = self.rules_loader.get_rules()
        matched_rule = None
        
        for rule in rules.get("dpi_signatures", []):
            if not rule.get("enabled", True):
                continue
                
            compiled_patterns = rule.get("compiled_patterns", [])
            for pattern in compiled_patterns:
                if pattern.search(payload_str):
                    matched_rule = rule
                    break
            
            if matched_rule:
                break
                
        if matched_rule:
            sig_name = matched_rule["name"]
            severity = matched_rule.get("severity", "High")
            sig_id = matched_rule.get("id")
            category = matched_rule.get("category")
            
            key = (src_ip, f"DPI_{sig_name}")
            if self._cooldown_ok(key, now):
                desc = f"{src_ip} sent malicious payload targeting port {dport}: {sig_name} signature matched."
                return self._process_alert(src_ip, "Deep Packet Inspection (L7)", severity, desc, now,
                                           method="static", rule_id=sig_id, category=category, layer="dpi")
        return None

    def _ml_cfg(self):
        return self._get_dynamic_config().get("model_learning", {})

    @staticmethod
    def _is_broadcast(dst_ip):
        # Ignore noisy local broadcast/multicast traffic (like mDNS 224.0.0.251)
        return bool(dst_ip) and (dst_ip.startswith("224.") or dst_ip.startswith("239.") or dst_ip.endswith(".255"))

    def observe_ml(self, info, now):
        """Window-mode ML: aggregates the packet; returns alerts for windows it closed."""
        if not self.ml_engine.ml_enabled or self.ml_aggregator is None or not self._is_dynamic_enabled():
            return []
        if self._is_broadcast(info.dst_ip):
            return []
        closed = self.ml_aggregator.add(info, now)
        return self._score_windows(closed, now) if closed else []

    def finish_ml(self, now):
        """Scores the still-open ML windows (end of a capture)."""
        if self.ml_aggregator is None or not self._is_dynamic_enabled():
            return []
        closed = self.ml_aggregator.close()
        return self._score_windows(closed, now) if closed else []

    def _is_clean(self, src_ip, window_start, now, horizon, max_reputation):
        """A window may train the model only if its source raised no rule alert
        within ``horizon`` seconds before (or during) it and its reputation
        score is below ``max_reputation``. Excluding sources for longer turns
        every rule false positive into an under-represented, "anomalous" host."""
        last = self._last_rule_alert.get(src_ip)
        if last is not None and last >= window_start - horizon:
            return False
        return self.reputation.get_score(src_ip, now) < max_reputation

    def _score_windows(self, closed, now):
        start, srcs, X, counts = closed
        cfg = self._ml_cfg()
        width = self.ml_aggregator.width
        self.ml_engine.maybe_retrain(now)
        # A model fitted (and calibrated) on a handful of windows is mostly
        # noise, so it neither alerts nor reports scores until it has seen enough.
        ready = self.ml_engine.trained_on >= cfg.get("min_train_windows", 500)
        scores = self.ml_engine.score_batch(X) if ready else None
        threshold = self.ml_engine.threshold
        clean_training = cfg.get("clean_training", True)
        horizon = cfg.get("clean_horizon_seconds", 10)
        max_reputation = cfg.get("clean_max_reputation", 50)
        min_packets = cfg.get("min_window_packets", 1)

        alerts = []
        for i, src in enumerate(srcs):
            rule_clean = not clean_training or self._is_clean(src, start, now, horizon, max_reputation)
            if rule_clean:
                self.ml_engine.add_calibration_sample(X[i].tolist())
            score = None if scores is None else float(scores[i])
            if self.score_sink is not None and score is not None:
                self.score_sink({"window_start": start, "window_seconds": width, "src_ip": src,
                                 "packets": counts[i], "score": score, "threshold": threshold})
            if score is not None and threshold is not None and score > threshold and counts[i] >= min_packets:
                if self._cooldown_ok((src, "ML_ANOMALY"), now):
                    desc = (f"Abnormal traffic window from {src}: {counts[i]} packets in {width:g}s, "
                            f"anomaly score {score:.3f} > {threshold:.3f}.")
                    a = self._process_alert(src, "AI Anomaly (Isolation Forest)", "Low", desc, now,
                                            method="ML", layer="ml")
                    a.update(timestamp=now, src_ip=src, dst_ip=None, protocol="WINDOW",
                             window_start=start, anomaly_score=score)
                    alerts.append(a)
            elif rule_clean:
                self.ml_engine.add_clean_sample(X[i].tolist())
        return alerts

    def check_ml_anomaly(self, src_ip, dst_ip, proto_name, packet_len, now, flags=None, dport=None):
        if not self.ml_engine.ml_enabled:
            return None

        self.ml_engine.maybe_retrain(now)
            
        if self._is_broadcast(dst_ip):
            return None
            
        # Per-IP packets per second tracker
        bucket = int(now)
        if self._last_bucket[src_ip] != bucket:
            self._last_bucket[src_ip] = bucket
            self._packet_count[src_ip] = 1
        else:
            self._packet_count[src_ip] += 1
            
        pps = self._packet_count[src_ip]
            
        last_t = self.last_seen.get(src_ip, now)
        current_iat = now - last_t if last_t else 1.0
        self.last_seen[src_ip] = now
        
        prev_iat = self.smoothed_iat[src_ip]
        ema_iat = 0.8 * prev_iat + 0.2 * current_iat
        self.smoothed_iat[src_ip] = ema_iat
        
        features = self.ml_engine.extract_features(packet_len, proto_name, ema_iat, flags, dport, pps)
        
        if self._is_dynamic_enabled():
            prediction = self.ml_engine.predict(features)
            
            # Require a minimum packet rate (default 10 pps) to trigger an ML anomaly
            # This prevents the AI from flagging random idle OS background noise
            if prediction == -1 and pps >= self.engine_settings()["ml_min_pps"]:
                key = (src_ip, "ML_ANOMALY")
                if self._cooldown_ok(key, now):
                    desc = f"Abnormal traffic pattern from {src_ip} (Avg IAT: {ema_iat:.4f}s, PPS: {pps})."
                    return self._process_alert(src_ip, "AI Anomaly (Isolation Forest)", "Low", desc, now,
                                           method="ML", layer="ml")
            else:
                self.ml_engine.add_clean_sample(features)
                
        return None
