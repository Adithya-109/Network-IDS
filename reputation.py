import time
import threading
import logging
import ipaddress
import subprocess

class BlockerBackend:
    def block(self, ip, ttl):
        pass
    def unblock(self, ip):
        pass

class DryRunBlocker(BlockerBackend):
    def block(self, ip, ttl):
        logging.info(f"[DryRunBlocker] WOULD BLOCK {ip} for {ttl} seconds")
        
    def unblock(self, ip):
        logging.info(f"[DryRunBlocker] WOULD UNBLOCK {ip}")

class IPTablesBlocker(BlockerBackend):
    def block(self, ip, ttl):
        try:
            # -I INPUT 1 inserts rule at top
            subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=False)
            logging.info(f"[IPTablesBlocker] BLOCKED {ip} for {ttl} seconds")
        except Exception as e:
            logging.error(f"[IPTablesBlocker] Failed to block {ip}: {e}")
            
    def unblock(self, ip):
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            logging.info(f"[IPTablesBlocker] UNBLOCKED {ip}")
        except Exception as e:
            logging.error(f"[IPTablesBlocker] Failed to unblock {ip}: {e}")

class ReputationManager:
    """Manages IP risk scores, escalation, and temporary blocking."""
    def __init__(self, block_ttl_seconds=300, dry_run=True, allowlist=None, background=True):
        self.block_ttl_seconds = block_ttl_seconds
        self.allowlist_cidrs = []
        if allowlist:
            for net in allowlist:
                try:
                    self.allowlist_cidrs.append(ipaddress.ip_network(net, strict=False))
                except Exception as e:
                    logging.error(f"[ReputationManager] Invalid allowlist entry {net}: {e}")
                    
        self.blocker = DryRunBlocker() if dry_run else IPTablesBlocker()
        self.scores = {} # src_ip -> (score, last_update_ts)
        self.blocks = {} # src_ip -> unblock_ts
        self._lock = threading.Lock()
        
        # Thread to clean up expired blocks. Offline replay passes
        # background=False and expiry is driven by packet time in add_alert.
        self.background = background
        self.running = background
        self._cleanup_thread = None
        if background:
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()
        
    def is_allowlisted(self, ip_str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in self.allowlist_cidrs:
                if ip_obj in net:
                    return True
        except ValueError:
            pass
        return False

    def get_score(self, src_ip, now):
        with self._lock:
            if src_ip not in self.scores:
                return 0.0
            score, last_ts = self.scores[src_ip]
            # Exponential decay: score halves every 60 seconds
            decay = 0.5 ** ((now - last_ts) / 60.0)
            return score * decay

    def add_alert(self, src_ip, severity, detection_type, now):
        """Adds score based on alert. Returns (new_score, block_applied)"""
        if self.is_allowlisted(src_ip):
            return 0.0, False
            
        weight = {"High": 100.0, "Medium": 50.0, "Low": 20.0}.get(severity, 10.0)

        if not self.background:
            self.expire(now)
        
        with self._lock:
            old_score = 0.0
            if src_ip in self.scores:
                old_score, last_ts = self.scores[src_ip]
                # Decay old score before adding
                decay = 0.5 ** ((now - last_ts) / 60.0)
                old_score *= decay
            
            new_score = old_score + weight
            self.scores[src_ip] = (new_score, now)
            
            # Check for blocking
            is_blocked = False
            if new_score >= 200.0: # Threshold for blocking
                if src_ip not in self.blocks or now >= self.blocks[src_ip]:
                    self.blocks[src_ip] = now + self.block_ttl_seconds
                    self.blocker.block(src_ip, self.block_ttl_seconds)
                else:
                    # Extend block
                    self.blocks[src_ip] = now + self.block_ttl_seconds
                is_blocked = True
                
            return new_score, is_blocked

    def expire(self, now):
        """Lifts every block whose TTL has passed at time ``now``."""
        with self._lock:
            expired = [ip for ip, unblock_ts in self.blocks.items() if now >= unblock_ts]
            for ip in expired:
                self.blocker.unblock(ip)
                del self.blocks[ip]

    def _cleanup_loop(self):
        while self.running:
            time.sleep(5)
            self.expire(time.time())
                    
    def update_config(self, block_ttl_seconds, dry_run, allowlist):
        with self._lock:
            self.block_ttl_seconds = block_ttl_seconds
            self.blocker = DryRunBlocker() if dry_run else IPTablesBlocker()
            
            self.allowlist_cidrs = []
            if allowlist:
                for net in allowlist:
                    try:
                        self.allowlist_cidrs.append(ipaddress.ip_network(net, strict=False))
                    except Exception as e:
                        logging.error(f"[ReputationManager] Invalid allowlist entry {net}: {e}")

    def stop(self):
        self.running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)
