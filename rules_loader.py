import json
import os
import re
import threading
import time
import copy
import logging


def deep_merge(target, source):
    """Recursively merges ``source`` into ``target``; non-dict values replace."""
    for k, v in source.items():
        if isinstance(v, dict) and isinstance(target.get(k), dict):
            deep_merge(target[k], v)
        else:
            target[k] = copy.deepcopy(v)
    return target


class RulesLoader:
    """Loads and hot-reloads rules from rules.json and rules.d/ directory.

    ``overrides`` (e.g. from an experiment config) are deep-merged on top of
    the files on every load, so a replay run can change thresholds or toggle
    layers without editing rules.json."""
    def __init__(self, rules_path="rules.json", overrides=None):
        self.rules_path = rules_path
        self.overrides = overrides or {}
        self.rules_dir = os.path.join(os.path.dirname(rules_path), "rules.d")
        self.rules = {}
        self._lock = threading.Lock()
        self._last_mtime = 0
        self._last_dir_mtime = 0
        self.running = False
        self._thread = None
        self.load_rules()

    def get_rules(self):
        """Returns the current loaded rules (thread-safe)."""
        with self._lock:
            return self.rules

    def load_rules(self):
        """Attempt to load rules.json and rules.d/*.json."""
        new_rules = {
            "suspicious_ports": {},
            "dpi_signatures": [],
            "dynamic": {}
        }
        
        try:
            mtime = os.path.getmtime(self.rules_path)
        except OSError:
            mtime = 0

        try:
            with open(self.rules_path, "r") as f:
                data = json.load(f)
                self._merge_rules(new_rules, data)
        except Exception as e:
            logging.error(f"[RulesLoader] Failed to load {self.rules_path}: {e}")
            return False

        # Load from rules.d/
        dir_mtime = 0
        if os.path.isdir(self.rules_dir):
            try:
                dir_mtime = os.path.getmtime(self.rules_dir)
                for filename in os.listdir(self.rules_dir):
                    if filename.endswith(".json"):
                        filepath = os.path.join(self.rules_dir, filename)
                        try:
                            with open(filepath, "r") as f:
                                data = json.load(f)
                                self._merge_rules(new_rules, data)
                        except Exception as e:
                            logging.error(f"[RulesLoader] Failed to load {filepath}: {e}")
            except OSError:
                pass

        deep_merge(new_rules, self.overrides)

        # Compile regexes safely
        compiled_signatures = []
        for sig in new_rules.get("dpi_signatures", []):
            if not sig.get("enabled", True):
                continue
            
            patterns = sig.get("patterns", [])
            compiled_patterns = []
            valid_sig = True
            for p in patterns:
                if len(p) > 200: # Guard against overly complex/long regex
                    logging.warning(f"[RulesLoader] Regex too long in sig {sig.get('id', 'unknown')}: {p}")
                    valid_sig = False
                    break
                try:
                    compiled = re.compile(p, re.IGNORECASE)
                    compiled_patterns.append(compiled)
                except re.error as e:
                    logging.error(f"[RulesLoader] Invalid regex in sig {sig.get('id', 'unknown')}: {p} - {e}")
                    valid_sig = False
                    break
            
            if valid_sig:
                compiled_sig = sig.copy()
                compiled_sig["compiled_patterns"] = compiled_patterns
                compiled_signatures.append(compiled_sig)

        new_rules["dpi_signatures"] = compiled_signatures

        # Swap atomically
        with self._lock:
            old_rules = self.rules
            self.rules = new_rules
            self._last_mtime = mtime
            self._last_dir_mtime = dir_mtime

        self._log_diff(old_rules, new_rules)
        return True

    def _merge_rules(self, target, source):
        if "suspicious_ports" in source:
            target["suspicious_ports"].update(source["suspicious_ports"])
        
        if "dpi_signatures" in source:
            target["dpi_signatures"].extend(source["dpi_signatures"])
            
        if "dynamic" in source:
            # Simple dict update for dynamic config
            for k, v in source["dynamic"].items():
                if isinstance(v, dict) and k in target["dynamic"]:
                    target["dynamic"][k].update(v)
                else:
                    target["dynamic"][k] = v

        if "engine" in source:
            deep_merge(target.setdefault("engine", {}), source["engine"])

    def _log_diff(self, old_rules, new_rules):
        if not old_rules:
            logging.info("[RulesLoader] Initial rules loaded.")
            return
            
        old_sigs = {s.get("id"): s for s in old_rules.get("dpi_signatures", []) if s.get("id")}
        new_sigs = {s.get("id"): s for s in new_rules.get("dpi_signatures", []) if s.get("id")}
        
        added = set(new_sigs.keys()) - set(old_sigs.keys())
        removed = set(old_sigs.keys()) - set(new_sigs.keys())
        
        if added or removed:
            logging.info(f"[RulesLoader] Rules reloaded. Added: {len(added)}, Removed: {len(removed)}")

    def _watch_loop(self, poll_interval=5.0):
        while self.running:
            time.sleep(poll_interval)
            try:
                mtime = os.path.getmtime(self.rules_path)
                dir_mtime = 0
                if os.path.isdir(self.rules_dir):
                    dir_mtime = os.path.getmtime(self.rules_dir)
                    
                if mtime != self._last_mtime or dir_mtime != self._last_dir_mtime:
                    logging.info("[RulesLoader] Rules modification detected. Reloading...")
                    self.load_rules()
            except OSError:
                pass

    def start(self):
        if self.running:
            return
        self.running = True
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
