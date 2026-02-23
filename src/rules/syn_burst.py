from collections import defaultdict, deque
from typing import Deque, Dict, List
from typing import Optional
from models import Alert


class SYNBurstDetector:

    def __init__(self, window_s: int = 5, threshold_syn: int = 20, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_syn = threshold_syn
        self.thresholds = thresholds or {}

        # src_ip -> deque[timestamps]
        self.events: Dict[str, Deque[float]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str, tcp_flags: int) -> List[Alert]:
        SYN = 0x02
        ACK = 0x10

        # Only pure SYN (no ACK)
        if not (tcp_flags & SYN) or (tcp_flags & ACK):
            return []

        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

        syn_count = len(dq)

        if syn_count >= self.threshold_syn:

            if self.thresholds:
                if syn_count >= self.thresholds.get("high", 9999):
                    severity = "HIGH"
                elif syn_count >= self.thresholds.get("medium", self.threshold_syn):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "MEDIUM"

            alert = Alert(
                ts=ts,
                alert_type="SYN_BURST_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "threshold_syn": self.threshold_syn,
                    "syn_packets": syn_count,
                    "dst_ip": dst_ip,
                },
            )

            dq.clear()
            return [alert]

        return []