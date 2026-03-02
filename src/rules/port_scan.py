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

    def __init__(self, window_s: int = 15, threshold_ports: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        # Keep for display / backwards compatibility (medium-ish baseline)
        self.threshold_ports = threshold_ports
        self.thresholds = thresholds or {}

        # src_ip -> deque[(ts, dst_ip, dst_port)]
        self.events: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int) -> List[Alert]:
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

        alert = Alert(
            ts=ts,
            alert_type="PORT_SCAN_SUSPECTED",
            severity=severity,
            src_ip=src_ip,
            details={
                "window_s": self.window_s,
                # show thresholds that matter (handy for debugging)
                "thresholds": thresholds,
                "distinct_ports": count,
                "recent_target_sample": recent_sample,
            },
        )

        # Important behavior choice:
        # Clear only on MEDIUM/HIGH so LOW can "build up" into higher severity.

        return [alert]