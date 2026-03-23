# src/rules/dns_tunnel.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class DNSTunnelDetector:
    """
    Detects DNS tunneling via two signals:

    1. High query rate — tunneling tools (dnscat2, iodine) send many DNS queries
       rapidly to ferry data, far above normal resolver behaviour.

    2. Long query name — data is encoded in subdomain labels, producing unusually
       long fully-qualified domain names (e.g. base32-encoded payloads).

    Either signal alone can trigger an alert; both together raise severity.
    """

    INTERNAL_COOLDOWN_S = 10
    LONG_QUERY_THRESHOLD = 50  # characters in the queried domain name

    def __init__(self, window_s: int = 10, threshold_queries: int = 30, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_queries = threshold_queries
        self.thresholds = thresholds or {}

        # src_ip -> deque[timestamps]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)
        # src_ip -> {fire_key -> last_fire_ts}
        self._last_fire: Dict[str, Dict[str, float]] = defaultdict(dict)

    def process(self, ts: float, src_ip: str, dst_ip: str, qname: str) -> List[Alert]:
        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)
        name_len = len(qname)
        is_long_query = name_len >= self.LONG_QUERY_THRESHOLD

        low_th = int(self.thresholds.get("low", max(1, self.threshold_queries // 2)))
        rate_triggered = count >= low_th

        if not rate_triggered and not is_long_query:
            return []

        # Long query name alone (low query rate) warrants MEDIUM
        if is_long_query and not rate_triggered:
            fire_key = "long_query"
            if ts - self._last_fire[src_ip].get(fire_key, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][fire_key] = ts
            return [Alert(
                ts=ts,
                alert_type="DNS_TUNNEL_SUSPECTED",
                severity="MEDIUM",
                src_ip=src_ip,
                details={
                    "reason": "long_query_name",
                    "qname": qname,
                    "name_length": name_len,
                    "long_query_threshold": self.LONG_QUERY_THRESHOLD,
                },
            )]

        # Rate-based detection
        default_low = low_th
        default_medium = int(self.thresholds.get("medium", self.threshold_queries))
        default_high = int(self.thresholds.get("high", default_medium * 3))

        thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
        severity = classify(count, thresholds)

        if severity == "LOW":
            return []

        # Bump severity if long query name is also present
        if is_long_query and severity == "MEDIUM":
            severity = "HIGH"

        if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
            return []
        self._last_fire[src_ip][severity] = ts

        return [Alert(
            ts=ts,
            alert_type="DNS_TUNNEL_SUSPECTED",
            severity=severity,
            src_ip=src_ip,
            details={
                "reason": "high_query_rate" + ("+long_name" if is_long_query else ""),
                "window_s": self.window_s,
                "query_count": count,
                "thresholds": thresholds,
                "last_qname": qname,
                "name_length": name_len,
            },
        )]
