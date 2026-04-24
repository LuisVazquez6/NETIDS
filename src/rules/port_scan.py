# src/rules/port_scan.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple, Optional
from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class PortScanDetector:
    """
    Detects likely TCP port scans by tracking how many DISTINCT destination ports
    a source IP touches within a sliding time window.

    Emits LOW/MEDIUM/HIGH based on thresholds dict:
      thresholds = {"low": X, "medium": Y, "high": Z}
    """

    INTERNAL_COOLDOWN_S = 10
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    def __init__(self, window_s: int = 15, threshold_ports: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        # Keep for display / backwards compatibility (medium-ish baseline)
        self.threshold_ports = threshold_ports
        self.thresholds = thresholds or {}

        # src_ip -> deque[(ts, dst_ip, dst_port)]
        self.events: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)
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

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int) -> List[Alert]:
        try:
            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            dq = self.events[src_ip]
            dq.append((ts, dst_ip, dst_port))

            # expire old events
            cutoff = ts - self.window_s
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            distinct_ports = {p for (_, _, p) in dq}
            count = len(distinct_ports)

            recent_sample = list(distinct_ports)[:10]

            # Determine LOW threshold (so LOW alerts are possible)
            low_th = int(self.thresholds.get("low", max(1, self.threshold_ports // 2)))
            if count < low_th:
                return []

            default_low = low_th
            default_medium = int(self.thresholds.get("medium", self.threshold_ports))
            default_high = int(self.thresholds.get("high", default_medium * 3))

            thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
            severity = classify(count, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][severity] = ts

            return [Alert(
                ts=ts,
                alert_type="PORT_SCAN_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "thresholds": thresholds,
                    "distinct_ports": count,
                    "recent_target_sample": recent_sample,
                },
            )]
        except Exception:
            return []