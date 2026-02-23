from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple
from models import Alert

class ICMPFloodDetector:
    def __init__(self, window_s: int = 10, threshold_pkts: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_pkts = threshold_pkts
        self.thresholds = thresholds or {}
        self.events: Dict[str, Deque[float]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str) -> List[Alert]:
        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)

        if count >= self.threshold_pkts:
            if self.thresholds:
                if count >= self.thresholds.get("high", 999999):
                    severity = "HIGH"
                elif count >= self.thresholds.get("medium", self.threshold_pkts):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                    severity = "MEDIUM"

            alert = Alert(
                ts  = ts,
                alert_type = "ICMP_FLOOD_SUSPECTED",
                severity = severity,
                src_ip = src_ip,
                details = {
                    "window_s" : self.window_s,
                    "threshold_pkts" : self.threshold_pkts,
                    "thresholds" : self.thresholds,
                    "icmp_packets" : count,
                    "dst_ip" : dst_ip,
                },
            )
            dq.clear()
            return [alert]
                
        return []