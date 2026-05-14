# src/rules/icmp_sweep.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class ICMPSweepDetector:
    """
    Detects ICMP reconnaissance by counting ICMP echo requests received from a
    single source within a time window (host-based perspective: T1018).

    A burst of pings from one external host = active host discovery / probe.
    """

    INTERNAL_COOLDOWN_S = 15
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    def __init__(self, window_s: int = 30, threshold_hosts: int = 10, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.thresholds = thresholds or {}

        # src_ip -> deque[ts]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)
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

    def process(self, ts: float, src_ip: str, dst_ip: str) -> List[Alert]:
        try:
            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            dq = self.events[src_ip]
            dq.append(ts)

            cutoff = ts - self.window_s
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)

            low_th = int(self.thresholds.get("low", 5))
            if count < low_th:
                return []

            default_medium = int(self.thresholds.get("medium", 10))
            default_high   = int(self.thresholds.get("high", 30))
            thresholds = normalize_thresholds(self.thresholds, low_th, default_medium, default_high)
            severity   = classify(count, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][severity] = ts

            return [Alert(
                ts=ts,
                alert_type="ICMP_SWEEP_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s":    self.window_s,
                    "icmp_count":  count,
                    "thresholds":  thresholds,
                },
            )]
        except Exception:
            return []
