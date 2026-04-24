# src/rules/http_bruteforce.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class HTTPBruteForceDetector:
    """
    Detects HTTP brute-force login attempts by counting POST requests
    from the same source IP to the same destination within a sliding window.

    Requires TCP payload inspection — ids.py passes the Raw layer bytes.
    Common target ports: 80, 443, 8080, 8443.
    """

    INTERNAL_COOLDOWN_S = 10
    HTTP_PORTS = {80, 443, 8080, 8443}
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    def __init__(self, window_s: int = 20, threshold_requests: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_requests = threshold_requests
        self.thresholds = thresholds or {}

        # (src_ip, dst_ip, dst_port) -> deque[timestamps]
        self.events: Dict[Tuple, Deque[float]] = defaultdict(deque)
        # (src_ip, dst_ip, dst_port) -> {severity -> last_fire_ts}
        self._last_fire: Dict[Tuple, Dict[str, float]] = defaultdict(dict)
        self._last_seen: Dict[str, float] = {}

    def _cleanup(self, now: float) -> None:
        if len(self._last_seen) < self.MAX_TRACKED_IPS:
            return
        cutoff = now - self.IDLE_EXPIRY_S
        stale = [ip for ip, ts in self._last_seen.items() if ts < cutoff]
        for ip in stale:
            keys_to_remove = [k for k in self.events if k[0] == ip]
            for k in keys_to_remove:
                self.events.pop(k, None)
                self._last_fire.pop(k, None)
            del self._last_seen[ip]

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int, payload: bytes) -> List[Alert]:
        try:
            if dst_port not in self.HTTP_PORTS:
                return []

            # Accept both \r\n and \n line endings for HTTP method detection
            first_line = payload.split(b"\n")[0].rstrip(b"\r")
            if not first_line.startswith(b"POST"):
                return []

            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            key = (src_ip, dst_ip, dst_port)
            dq = self.events[key]
            dq.append(ts)

            cutoff = ts - self.window_s
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)

            low_th = int(self.thresholds.get("low", max(1, self.threshold_requests // 2)))
            if count < low_th:
                return []

            default_low = low_th
            default_medium = int(self.thresholds.get("medium", self.threshold_requests))
            default_high = int(self.thresholds.get("high", default_medium * 3))

            thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
            severity = classify(count, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[key].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[key][severity] = ts

            try:
                request_line = first_line.decode("utf-8", errors="replace")
            except Exception:
                request_line = "unknown"

            return [Alert(
                ts=ts,
                alert_type="HTTP_BRUTEFORCE_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "post_count": count,
                    "dst_port": dst_port,
                    "request_line": request_line,
                    "thresholds": thresholds,
                },
            )]
        except Exception:
            return []
