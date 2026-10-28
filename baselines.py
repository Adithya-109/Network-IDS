import copy
import time
import math
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass(frozen=True)
class ThresholdParams:
    """Per-metric limits a tracker turns its statistics into a threshold with."""
    k_sigma: float
    floor: float
    ceiling: float
    static: float      # operator's fixed threshold (config.py), used while cold
    warmup: int        # samples before a tracker's own statistics are trusted
    max_rise: float    # drift-bounded trackers: max upward move of mean/std per sample

    def clamp(self, value):
        return min(max(value, self.floor), self.ceiling)

class LRUTTLCache:
    """A simple thread-safe LRU cache with TTL eviction.

    Every method takes an optional ``now`` so offline PCAP replay can drive
    expiry from packet timestamps; it falls back to the wall clock."""
    def __init__(self, maxsize=10000, ttl=300):
        self.maxsize = maxsize
        self.ttl = ttl
        self.cache = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key, now=None):
        now = time.time() if now is None else now
        with self._lock:
            if key in self.cache:
                val, timestamp = self.cache[key]
                if now - timestamp > self.ttl:
                    del self.cache[key]
                    return None
                self.cache.move_to_end(key)
                self.cache[key] = (val, now) # Update timestamp
                return val
            return None

    def set(self, key, value, now=None):
        now = time.time() if now is None else now
        with self._lock:
            self.cache[key] = (value, now)
            self.cache.move_to_end(key)
            if len(self.cache) > self.maxsize:
                self.cache.popitem(last=False)

    def prune(self, now=None):
        now = time.time() if now is None else now
        with self._lock:
            keys_to_delete = []
            for k, (v, ts) in self.cache.items():
                if now - ts > self.ttl:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self.cache[k]


class BaselineTracker:
    """Tracks EMA mean and variance for a specific metric over time."""
    def __init__(self, alpha=0.1):
        self.alpha = alpha
        self.mean = None
        self.var = 0.0
        self.samples = 0

    def update(self, value):
        self.samples += 1
        if self.mean is None:
            self.mean = float(value)
            self.var = 0.0
        else:
            diff = value - self.mean
            self.mean += self.alpha * diff
            self.var = (1 - self.alpha) * (self.var + self.alpha * diff * diff)

    @property
    def std(self):
        return math.sqrt(self.var)

    def observe(self, value, params=None):
        self.update(value)

    def threshold(self, params):
        return self.get_threshold(params.k_sigma, params.floor, params.ceiling)

    def get_threshold(self, k_sigma, floor, ceiling, is_warm=True):
        if not is_warm or self.mean is None:
            return ceiling # Fall back to static threshold (ceiling) when warming up

        std_dev = math.sqrt(self.var)
        thresh = self.mean + k_sigma * std_dev
        
        if thresh < floor:
            return floor
        if thresh > ceiling:
            return ceiling
        return thresh


class BoundedEMA:
    """EMA mean/std whose upward movement per sample is capped.

    Decreases are unrestricted, but each sample can raise the mean and the
    std by at most ``max_rise``, so a threshold mean + k*std rises by at most
    (1 + k) * max_rise per sample. A slow-ramp ("boiling frog") attacker can
    therefore only move it linearly, never geometrically as with a plain EMA.
    The first sample is capped at the operator's static threshold."""
    def __init__(self, alpha):
        self.alpha = alpha
        self.mean = None
        self.std = 0.0
        self.samples = 0

    def update(self, value, start_cap, max_rise):
        self.samples += 1
        if self.mean is None:
            self.mean = min(float(value), start_cap)
            self.std = 0.0
            return
        diff = value - self.mean
        new_std = math.sqrt((1 - self.alpha) * (self.std ** 2 + self.alpha * diff * diff))
        self.mean += min(self.alpha * diff, max_rise)
        self.std = min(new_std, self.std + max_rise)

    def threshold(self, params):
        return params.clamp(self.mean + params.k_sigma * self.std)


class DriftBoundedTracker:
    """Fast drift-bounded baseline plus a slow long-term reference.

    The fast baseline sets the detection threshold. The reference learns
    ``ref_alpha / alpha`` times slower and only from samples below its own
    threshold, so it stays behind when the fast baseline is walked upwards.
    ``drifted`` reports when the fast mean has left the reference's normal
    range, a sign of either poisoning or real (benign) concept drift."""
    def __init__(self, alpha=0.1, ref_alpha=0.01):
        self.fast = BoundedEMA(alpha)
        self.ref = BoundedEMA(ref_alpha)

    @property
    def samples(self):
        return self.fast.samples

    @property
    def mean(self):
        return self.fast.mean

    @property
    def std(self):
        return self.fast.std

    def observe(self, value, params):
        if self.ref.mean is None or value < self.ref.threshold(params):
            ref_rise = params.max_rise * self.ref.alpha / self.fast.alpha
            self.ref.update(value, params.static, ref_rise)
        self.fast.update(value, params.static, params.max_rise)

    def threshold(self, params):
        return self.fast.threshold(params)

    def reference_threshold(self, params):
        return self.ref.threshold(params) if self.ref.mean is not None else None

    def drifted(self, params):
        return (self.ref.samples >= params.warmup and self.fast.mean is not None
                and self.fast.mean > self.ref.threshold(params))

    def rollback(self):
        """Resets the fast baseline to the reference (undoes a suspected poisoning)."""
        self.fast.mean, self.fast.std = self.ref.mean, self.ref.std


class MADTracker:
    """Median + k * 1.4826 * MAD over the last ``history`` samples.

    Robust statistics: moving the median takes poisoning more than half of the
    history, but once that happens the threshold follows."""
    def __init__(self, history=100):
        self.values = deque(maxlen=history)
        self.samples = 0
        self.mean = None  # the median, named for a uniform tracker interface
        self.std = 0.0    # 1.4826 * MAD (consistent with sigma for normal data)

    def observe(self, value, params=None):
        self.values.append(float(value))
        self.samples += 1
        ordered = sorted(self.values)
        self.mean = _median(ordered)
        self.std = 1.4826 * _median(sorted(abs(v - self.mean) for v in ordered))

    def threshold(self, params):
        return params.clamp(self.mean + params.k_sigma * self.std)


def _median(ordered):
    n = len(ordered)
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def tracker_factory(th_cfg):
    """Builds the tracker constructor selected by adaptive_thresholds.method."""
    method = th_cfg.get("method", "ema")
    alpha = th_cfg.get("alpha", 0.1)
    if method == "ema":
        return lambda: BaselineTracker(alpha=alpha)
    if method == "drift_bounded":
        ref_alpha = th_cfg.get("drift", {}).get("ref_alpha", 0.01)
        return lambda: DriftBoundedTracker(alpha=alpha, ref_alpha=ref_alpha)
    if method == "mad":
        history = th_cfg.get("mad", {}).get("history", 100)
        return lambda: MADTracker(history=history)
    raise ValueError(f"unknown adaptive_thresholds.method: {method}")


class AdaptiveThresholds:
    """Manages baselines for multiple IPs and metrics.

    With ``population_prior`` every metric also keeps a population baseline
    learned from all sources' normal samples, and a source seen for the first
    time starts from a copy of it instead of from nothing (once it is warm)."""
    def __init__(self, max_ips=10000, ttl=600, factory=BaselineTracker, population_prior=False):
        self.cache = LRUTTLCache(maxsize=max_ips, ttl=ttl)
        self.factory = factory
        self.population_prior = population_prior
        self.populations = {}

    def population(self, metric_name):
        if metric_name not in self.populations:
            self.populations[metric_name] = self.factory()
        return self.populations[metric_name]

    def get_tracker(self, src_ip, metric_name, now=None, warmup=None):
        key = f"{src_ip}_{metric_name}"
        tracker = self.cache.get(key, now)
        if not tracker:
            pop = self.populations.get(metric_name)
            if self.population_prior and pop is not None and warmup is not None and pop.samples >= warmup:
                tracker = copy.deepcopy(pop)
            else:
                tracker = self.factory()
            self.cache.set(key, tracker, now)
        return tracker

    def update_baseline(self, src_ip, metric_name, value, now=None, params=None):
        """Updates the baseline with a *normal* (non-malicious) measurement."""
        tracker = self.get_tracker(src_ip, metric_name, now, params.warmup if params else None)
        tracker.observe(value, params)
        if self.population_prior:
            self.population(metric_name).observe(value, params)
        self.cache.set(f"{src_ip}_{metric_name}", tracker, now) # refresh TTL
        return tracker
