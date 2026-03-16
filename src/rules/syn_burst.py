# src/rules/syn_burst.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional
from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class SYNBurstDetector:
    """
    Detects SYN bursts (many SYN-only packets from one src within a time window).
    Best fed only TCP packets; we further filter to SYN without ACK inside process().
    """

    INTERNAL_COOLDOWN_S = 10

    def __init__(self, window_s: int = 5, threshold_syn: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        # kept for compatibility / debugging
        self.threshold_syn = threshold_syn
        self.thresholds = thresholds or {}

        # src_ip -> deque[timestamps]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)
        # src_ip -> {severity -> last_fire_ts}
        self._last_fire: Dict[str, Dict[str, float]] = defaultdict(dict)

    def process(self, ts: float, src_ip: str, dst_ip: str, flags: int) -> List[Alert]:
        # Count only SYN without ACK as "attempt-like" burst
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0
        if not (is_syn and not is_ack):
            return []

        ##print(f"[DBG] src={src_ip} flags={flags} is_syn={is_syn} is_ack={is_ack}")

        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        ##print(f"[DBG] count={count} window_s={self.window_s} thresholds={self.thresholds}")

        low_th = int(self.thresholds.get("low", max(1, self.threshold_syn // 2)))
        if count < low_th:
            return []

        default_low = low_th
        default_medium = int(self.thresholds.get("medium", self.threshold_syn))
        default_high = int(self.thresholds.get("high", default_medium * 3))


        # Ensure classify always has a usable dict
        thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
        severity = classify(count, thresholds)

        if severity == "LOW":
            return []

        if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
            return []
        self._last_fire[src_ip][severity] = ts

        alert = Alert(
            ts=ts,
            alert_type="SYN_BURST_SUSPECTED",
            severity=severity,
            src_ip=src_ip,
            details={
                "window_s": self.window_s,
                "syn_count": count,
                "thresholds": thresholds
            },
        )

        

        return [alert]