import time
import threading
import logging
import os
import random
import joblib
from collections import deque
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class MLAnomalyEngine:
    def __init__(self, retrain_interval_seconds=60, window_size=5000, contamination="auto", persist_dir=".",
                 persist=True, background=True, seed=42, n_estimators=100,
                 buffer="recent", target_fpr=None, model_filename="model.joblib"):
        self.retrain_interval_seconds = retrain_interval_seconds
        self.window_size = window_size
        self.contamination = contamination
        self.persist_dir = persist_dir
        # Offline experiments run with persist=False (never load or overwrite
        # model.joblib, so runs can't leak state into each other) and
        # background=False (retraining is scheduled on packet time through
        # maybe_retrain, which makes a replay deterministic).
        self.persist = persist
        self.background = background
        self.seed = seed
        self.n_estimators = n_estimators
        self._last_train_ts = None
        # buffer="recent" keeps the last window_size samples; "reservoir" keeps
        # a uniform sample of every clean sample seen, so long-past normal
        # behaviour isn't forgotten after a busy (or attacker-shaped) hour.
        self.buffer_mode = buffer
        self._rng = random.Random(seed)
        self._seen = 0
        # With target_fpr, each retrain sets the alert threshold to the
        # (1 - target_fpr) quantile of the new model's anomaly scores on the
        # calibration reservoir; contamination is then unused. The training
        # buffer leaves out windows the model itself flagged (so it can't
        # learn the attacks it catches), but that truncates exactly the tail
        # the threshold is set in; the calibration reservoir keeps them, so
        # the threshold matches the real distribution of clean windows.
        self.target_fpr = target_fpr
        self.calibration_buffer = []
        self._calib_seen = 0
        self.threshold = None
        self.trained_on = 0  # samples the current model was fitted on
        
        self.ml_enabled = ML_AVAILABLE
        self.model = None
        self.is_trained = False
        self._lock = threading.Lock()
        
        # Buffer of clean features
        self.training_buffer = deque(maxlen=self.window_size) if buffer == "recent" else []
        
        self.running = False
        self._thread = None
        
        self.model_path = os.path.join(persist_dir, model_filename)
        if self.persist:
            self.load_model()
        
    def load_model(self):
        if not self.ml_enabled:
            return
        try:
            if os.path.exists(self.model_path):
                with self._lock:
                    loaded = joblib.load(self.model_path)
                    if isinstance(loaded, dict):  # calibrated model: {"model", "threshold"}
                        self.model, self.threshold = loaded["model"], loaded["threshold"]
                    else:
                        self.model = loaded
                    self.is_trained = True
                logging.info("[MLEngine] Loaded existing model from disk.")
        except Exception as e:
            logging.error(f"[MLEngine] Failed to load model: {e}")

    def save_model(self):
        if not self.persist:
            return
        try:
            with self._lock:
                if self.model:
                    # Write to a temp file then rename for atomic save
                    temp_path = self.model_path + ".tmp"
                    payload = self.model
                    if self.target_fpr is not None:
                        payload = {"model": self.model, "threshold": self.threshold}
                    joblib.dump(payload, temp_path)
                    os.replace(temp_path, self.model_path)
        except Exception as e:
            logging.error(f"[MLEngine] Failed to save model: {e}")

    def add_clean_sample(self, features):
        if not self.ml_enabled:
            return
        with self._lock:
            if self.buffer_mode == "recent":
                self.training_buffer.append(features)
                return
            self._seen += 1
            if len(self.training_buffer) < self.window_size:
                self.training_buffer.append(features)
            else:
                j = self._rng.randrange(self._seen)
                if j < self.window_size:
                    self.training_buffer[j] = features

    def extract_features(self, pkt_len, proto_name, ema_iat, flags, dport, pps):
        is_tcp = 1 if proto_name == "TCP" else 0
        is_udp = 1 if proto_name == "UDP" else 0
        is_icmp = 1 if proto_name == "ICMP" else 0
        
        # Bucketize port
        port_bucket = 0
        if dport is not None:
            if dport < 1024:
                port_bucket = 1
            elif dport < 10000:
                port_bucket = 2
            else:
                port_bucket = 3
                
        # Return list of features
        flags_int = int(flags) if flags is not None else 0
        return [pkt_len, ema_iat, is_tcp, is_udp, is_icmp, flags_int, port_bucket, pps]

    def predict(self, features):
        if not self.ml_enabled or not self.is_trained:
            return 1 # 1 means normal
        
        with self._lock:
            if not self.model:
                return 1
            try:
                # model.predict expects a 2D array
                return self.model.predict([features])[0]
            except Exception as e:
                logging.error(f"[MLEngine] Prediction error: {e}")
                return 1

    def add_calibration_sample(self, features):
        """Reservoir of rule-clean samples, including ones the model flagged."""
        if not self.ml_enabled or self.target_fpr is None:
            return
        with self._lock:
            self._calib_seen += 1
            if len(self.calibration_buffer) < self.window_size:
                self.calibration_buffer.append(features)
            else:
                j = self._rng.randrange(self._calib_seen)
                if j < self.window_size:
                    self.calibration_buffer[j] = features

    def score_batch(self, X):
        """Anomaly scores (higher = more anomalous) for a 2D batch, or None before training."""
        if not self.ml_enabled or not self.is_trained:
            return None
        with self._lock:
            if not self.model:
                return None
            try:
                return -self.model.score_samples(X)
            except Exception as e:
                logging.error(f"[MLEngine] Scoring error: {e}")
                return None

    def retrain_once(self):
        """Fits a fresh Isolation Forest on the current buffer. Returns True if a model was trained."""
        if not self.ml_enabled:
            return False

        with self._lock:
            buffer_copy = list(self.training_buffer)
            calib_copy = list(self.calibration_buffer) or buffer_copy
            
        if len(buffer_copy) < min(100, self.window_size // 10):
            # Not enough data to retrain
            return False
            
        try:
            train = buffer_copy
            new_model = self._new_forest()
            new_model.fit(train)
            threshold = None
            if self.target_fpr is not None:
                scores = -new_model.score_samples(calib_copy)
                threshold = float(np.quantile(scores, 1 - self.target_fpr))
            
            with self._lock:
                self.model = new_model
                self.threshold = threshold
                self.trained_on = len(train)
                self.is_trained = True
            
            self.save_model()
            logging.info(f"[MLEngine] Retrained model on {len(buffer_copy)} samples.")
            return True
        except Exception as e:
            logging.error(f"[MLEngine] Retraining failed: {e}")
            return False

    def _new_forest(self):
        return IsolationForest(
            n_estimators=self.n_estimators,
            contamination="auto" if self.target_fpr is not None else self.contamination,
            random_state=self.seed,
        )

    def maybe_retrain(self, now):
        """Packet-time retraining schedule used when background=False."""
        if self.background:
            return False
        if self._last_train_ts is None:
            self._last_train_ts = now
            return False
        if now - self._last_train_ts < self.retrain_interval_seconds:
            return False
        self._last_train_ts = now
        return self.retrain_once()

    def _retrain_loop(self):
        while self.running:
            time.sleep(self.retrain_interval_seconds)
            self.retrain_once()

    def start(self):
        if not self.ml_enabled or self.running or not self.background:
            return
        self.running = True
        self._thread = threading.Thread(target=self._retrain_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
            
    def update_config(self, interval, window, contamination):
        with self._lock:
            self.retrain_interval_seconds = interval
            self.window_size = window
            self.contamination = contamination
            # Note: The deque maxlen cannot be easily changed in place without recreating
            if self.buffer_mode != "recent":
                del self.training_buffer[window:]
            elif self.training_buffer.maxlen != window:
                old_items = list(self.training_buffer)[-window:]
                self.training_buffer = deque(old_items, maxlen=window)
