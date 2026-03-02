# src/rules/icmp_flood.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class ICMPFloodDetector:
    """
    Detects ICMP echo-request floods by counting events from src_ip in a time window.
    ids.py already filters ICMP type 8 (echo request) before calling this.
    """

    def __init__(self, window_s: int = 10, threshold_pkts: int = 50, thresholds: Optional[dict] = None):
        self.window_s = window_s
        # kept for compatibility / debugging
        self.threshold_pkts = threshold_pkts
        self.thresholds = thresholds or {}

        # src_ip -> deque[timestamps]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str) -> List[Alert]:
        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)

        low_th = int(self.thresholds.get("low", max(1, self.threshold_pkts // 2)))
        if count < low_th:
            return []

        default_low = low_th
        default_medium = int(self.thresholds.get("medium", self.threshold_pkts))
        default_high = int(self.thresholds.get("high", default_medium * 3))

        thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
        severity = classify(count, thresholds)

        if severity == "LOW":
            return []

        alert = Alert(
            ts=ts,
            alert_type="ICMP_FLOOD_SUSPECTED",
            severity=severity,
            src_ip=src_ip,
            details={
                "window_s": self.window_s,
                "pkt_count": count,
                "thresholds": {
                    "low": int(thresholds.get("low", low_th)),
                    "medium": int(thresholds.get("medium", self.threshold_pkts)),
                    "high": int(thresholds.get("high", int(thresholds.get("medium", self.threshold_pkts)) * 3)),
                },
            },
        )


        return [alert]