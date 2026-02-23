from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional

from models import Alert


class SSHBruteForceDetector:
    """
    Detects potential SSH brute-force attacks by monitoring repeated NEW SSH connection attempts
    (SYN packets to port 22 without ACK) from the same source IP within a specified time window.
    """

    def __init__(self, window_s: int = 30, threshold_hits: int = 12, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_hits = threshold_hits
        self.thresholds = thresholds or {}
        self.events: Dict[str, Deque[float]] = defaultdict(deque)

    def process(self, ts: float, src_ip: str, dst_ip: str, dst_port: int, flags: int) -> List[Alert]:
        # Only look at SSH
        if dst_port != 22:
            return []

        # SYN without ACK is a decent "new attempt" signal
        # scapy flags bitmask: SYN=0x02, ACK=0x10
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0
        if (not is_syn) or is_ack:
            return []

        dq = self.events[src_ip]
        dq.append(ts)

        cutoff = ts - self.window_s
        while dq and dq[0] < cutoff:
            dq.popleft()

        count = len(dq)

        if count >= self.threshold_hits:
            # severity tiering
            if self.thresholds:
                if count >= self.thresholds.get("high", 9999):
                    severity = "HIGH"
                elif count >= self.thresholds.get("medium", self.threshold_hits):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "MEDIUM"

            alert = Alert(
                ts=ts,
                alert_type="SSH_BRUTE_FORCE_SUSPECTED",
                severity=severity,
                src_ip=src_ip,
                details={
                    "window_s": self.window_s,
                    "threshold_hits": self.threshold_hits,
                    "attempts": count,
                    "dst_ip": dst_ip,
                    "note": "Heuristic: multiple new SYN attempts to port 22 from same source within short time window.",
                },
            )
            dq.clear()
            return [alert]

        return []