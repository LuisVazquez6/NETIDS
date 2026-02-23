from __future__ import annotations
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple
from models import Alert


class PortScanDetector:

    def __init__(self, window_s: int = 15, threshold_ports: int = 20, thresholds: dict | None = None):
        self.window_s = window_s
        self.threshold_ports = threshold_ports
        self.thresholds = thresholds or {}

        # src_ip -> deque[(ts, dst_ip, dst_port)]
        self.events: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int) -> List[Alert]:
        dq = self.events[src_ip]
        dq.append((ts, dst_ip, dst_port))

        cutoff = ts - self.window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        distinct_ports = {p for (_, _, p) in dq}

        if len(distinct_ports) >= self.threshold_ports:

            # Determine severity using thresholds dict
            if self.thresholds:
                if len(distinct_ports) >= self.thresholds.get("high", 9999):
                    severity = "HIGH"
                elif len(distinct_ports) >= self.thresholds.get("medium", self.threshold_ports):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "MEDIUM"

            alert = Alert(
                ts=ts,
                alert_type="PORT_SCAN_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "threshold_ports": self.threshold_ports,
                    "distinct_ports": len(distinct_ports),
                    "recent_target_sample": list({(d, p) for (_, d, p) in list(dq)[-20:]})[:12],
                },
            )

            dq.clear()
            return [alert]

        return []