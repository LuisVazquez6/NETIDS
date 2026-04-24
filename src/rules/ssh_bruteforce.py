# src/rules/ssh_bruteforce.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class SSHBruteForceDetector:
    """
    Detects potential SSH brute-force by counting SYN-only packets to port 22
    from the same source within a time window.

    NOTE: This is a network-level heuristic. True "failed logins" would require
    host logs, but this is SOC-valid for traffic-based detection in a lab.
    """

    INTERNAL_COOLDOWN_S = 10
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    def __init__(self, window_s: int = 30, threshold_hits: int = 12, thresholds: Optional[dict] = None):
        self.window_s = window_s
        # kept for compatibility / debugging
        self.threshold_hits = threshold_hits
        self.thresholds = thresholds or {}

        # src_ip -> deque[timestamps]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)
        # src_ip -> {severity -> last_fire_ts}
        self._last_fire: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._last_seen: Dict[str, float] = {}

    def _cleanup(self, now: float) -> None:
        if len(self._last_seen) < self.MAX_TRACKED_IPS:
            return
        cutoff = now - self.IDLE_EXPIRY_S
        stale = [ip for ip, ts in self._last_seen.items() if ts < cutoff]
        for ip in stale:
            self.events.pop(ip, None)
            self._last_fire.pop(ip, None)
            del self._last_seen[ip]

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int, flags: int) -> List[Alert]:
        try:
            # Only look at SSH
            if dst_port != 22:
                return []

            # Only count SYN without ACK as attempt-like
            is_syn = (flags & 0x02) != 0
            is_ack = (flags & 0x10) != 0
            if not (is_syn and not is_ack):
                return []

            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            dq = self.events[src_ip]
            dq.append(ts)

            cutoff = ts - self.window_s
            while dq and dq[0] < cutoff:
                dq.popleft()

            attempts = len(dq)

            low_th = int(self.thresholds.get("low", max(1, self.threshold_hits // 2)))
            if attempts < low_th:
                return []

            default_low = low_th
            default_medium = int(self.thresholds.get("medium", self.threshold_hits))
            default_high = int(self.thresholds.get("high", default_medium * 3))

            thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
            severity = classify(attempts, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][severity] = ts

            return [Alert(
                ts=ts,
                alert_type="SSH_BRUTEFORCE_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "attempts": attempts,
                    "dst_port": 22,
                    "thresholds": {
                        "low": int(thresholds.get("low", low_th)),
                        "medium": int(thresholds.get("medium", self.threshold_hits)),
                        "high": int(thresholds.get("high", int(thresholds.get("medium", self.threshold_hits)) * 3)),
                    },
                },
            )]
        except Exception:
            return []