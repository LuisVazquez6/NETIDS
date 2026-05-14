# src/rules/lateral_movement.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Set, Tuple

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class LateralMovementDetector:
    """
    Detects lateral movement by counting connection attempts from a single source
    to administrative ports on this host (SSH, RDP, Telnet, WinRM).

    Distinct from SYN burst (which floods one port for DoS) and port scan (which
    probes many arbitrary ports). Lateral movement probes known admin services
    specifically, indicating credential theft or pivot attempts (T1021).

    Monitored admin ports:
      22   — SSH
      23   — Telnet
      3389 — RDP
      5985 — WinRM (HTTP)
      5986 — WinRM (HTTPS)
    """

    ADMIN_PORTS: Set[int] = {22, 23, 3389, 5985, 5986}
    INTERNAL_COOLDOWN_S = 15
    MAX_TRACKED_IPS = 5000
    IDLE_EXPIRY_S = 300

    PORT_NAMES = {22: "SSH", 23: "Telnet", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-S"}

    def __init__(self, window_s: int = 60, threshold_hosts: int = 8, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.thresholds = thresholds or {}

        # src_ip -> deque[(ts, dst_port)]
        self.events: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
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
            if dst_port not in self.ADMIN_PORTS:
                return []

            # Only count SYN-only packets (connection attempts, not established sessions)
            is_syn = (flags & 0x02) != 0
            is_ack = (flags & 0x10) != 0
            if not (is_syn and not is_ack):
                return []

            self._last_seen[src_ip] = ts
            self._cleanup(ts)

            dq = self.events[src_ip]
            dq.append((ts, dst_port))

            cutoff = ts - self.window_s
            while dq and dq[0][0] < cutoff:
                dq.popleft()

            count = len(dq)
            ports_seen = {p for (_, p) in dq}
            port_names = [self.PORT_NAMES.get(p, str(p)) for p in sorted(ports_seen)]

            low_th = int(self.thresholds.get("low", 4))
            if count < low_th:
                return []

            default_medium = int(self.thresholds.get("medium", 8))
            default_high   = int(self.thresholds.get("high", 20))
            thresholds = normalize_thresholds(self.thresholds, low_th, default_medium, default_high)
            severity   = classify(count, thresholds)

            if severity == "LOW":
                return []

            if ts - self._last_fire[src_ip].get(severity, 0.0) < self.INTERNAL_COOLDOWN_S:
                return []
            self._last_fire[src_ip][severity] = ts

            return [Alert(
                ts=ts,
                alert_type="LATERAL_MOVEMENT_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s":    self.window_s,
                    "attempt_count": count,
                    "admin_ports": port_names,
                    "thresholds":  thresholds,
                },
            )]
        except Exception:
            return []
