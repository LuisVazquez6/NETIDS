# src/rules/slow_loris.py
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class SlowLorisDetector:
    """
    Detects Slow Loris / slow HTTP attacks by tracking half-open TCP connections.

    A connection is "half-open" when a SYN is seen from a source but no FIN
    or RST has closed it. Slow Loris tools open many such connections and send
    partial HTTP headers to keep them alive indefinitely, exhausting the server's
    connection pool without triggering a SYN flood detector.

    Fires when the number of concurrent half-open connections from a single source
    exceeds the configured threshold.
    """

    INTERNAL_COOLDOWN_S = 10
    CONN_EXPIRY_S = 120  # drop stale tracked connections after 2 minutes
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    def __init__(self, threshold_connections: int = 20, thresholds: Optional[dict] = None):
        self.threshold_connections = threshold_connections
        self.thresholds = thresholds or {}

        # src_ip -> {(src_port, dst_ip, dst_port): open_ts}
        self._open_conns: Dict[str, Dict[Tuple, float]] = defaultdict(dict)
        # src_ip -> {severity -> last_fire_ts}
        self._last_fire: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._last_seen: Dict[str, float] = {}

    def _cleanup(self, now: float) -> None:
        if len(self._last_seen) < self.MAX_TRACKED_IPS:
            return
        cutoff = now - self.IDLE_EXPIRY_S
        stale = [ip for ip, ts in self._last_seen.items() if ts < cutoff]
        for ip in stale:
            self._open_conns.pop(ip, None)
            self._last_fire.pop(ip, None)
            del self._last_seen[ip]

    def process(self, ts: float, src_ip: str, dst_ip: str, src_port: int, dst_port: int, flags: int) -> List[Alert]:
        try:
            is_syn = (flags & 0x02) != 0
            is_ack = (flags & 0x10) != 0
            is_fin = (flags & 0x01) != 0
            is_rst = (flags & 0x04) != 0

            # Include dst_ip in the key to avoid false matches across different servers
            conn_key = (src_port, dst_ip, dst_port)
            conns = self._open_conns[src_ip]

            if is_syn and not is_ack:
                conns[conn_key] = ts
            elif is_fin or is_rst:
                conns.pop(conn_key, None)

            # Expire stale connections
            cutoff = ts - self.CONN_EXPIRY_S
            stale = [k for k, open_ts in conns.items() if open_ts < cutoff]
            for k in stale:
                del conns[k]

            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            count = len(conns)

            low_th = int(self.thresholds.get("low", max(1, self.threshold_connections // 2)))
            if count < low_th:
                return []

            default_low = low_th
            default_medium = int(self.thresholds.get("medium", self.threshold_connections))
            default_high = int(self.thresholds.get("high", default_medium * 2))

            thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
            severity = classify(count, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][severity] = ts

            return [Alert(
                ts=ts,
                alert_type="SLOW_LORIS_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "half_open_connections": count,
                    "thresholds": thresholds,
                },
            )]
        except Exception:
            return []
