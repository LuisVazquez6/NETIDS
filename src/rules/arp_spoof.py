# src/rules/arp_spoof.py
from __future__ import annotations

from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from models.alerts import Alert
from utils.severity import classify, normalize_thresholds


class ARPSpoofDetector:
    """
    Detects ARP spoofing by tracking IP -> MAC mappings.

    Fires on two conditions:
      1. IP-MAC conflict: same IP seen with a different MAC (classic ARP poisoning).
      2. Gratuitous ARP flood: rapid unsolicited ARP replies from the same MAC
         (attacker broadcasting false mappings to the whole segment).
    """

    INTERNAL_COOLDOWN_S = 10

    def __init__(self, window_s: int = 30, threshold_gratuitous: int = 10, thresholds: Optional[dict] = None):
        self.window_s = window_s
        self.threshold_gratuitous = threshold_gratuitous
        self.thresholds = thresholds or {}

        # ip -> set of MACs seen for that IP
        self._ip_mac_map: Dict[str, set] = defaultdict(set)
        # src_mac -> deque[timestamps] of gratuitous ARP events
        self._gratuitous: Dict[str, Deque[float]] = defaultdict(deque)
        # (reason, key, severity) -> last_fire_ts
        self._last_fire: Dict[Tuple, float] = defaultdict(float)

    def process(self, ts: float, src_ip: str, src_mac: str, dst_mac: str, op: int) -> List[Alert]:
        alerts: List[Alert] = []

        # op=1 is ARP request, op=2 is ARP reply
        is_reply = op == 2
        is_broadcast_dst = dst_mac.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")
        is_gratuitous = is_reply and is_broadcast_dst

        # --- Condition 1: IP-MAC conflict ---
        known_macs = self._ip_mac_map[src_ip]
        if known_macs and src_mac not in known_macs:
            fire_key = ("conflict", src_ip, "HIGH")
            if ts - self._last_fire[fire_key] >= self.INTERNAL_COOLDOWN_S:
                self._last_fire[fire_key] = ts
                alerts.append(Alert(
                    ts=ts,
                    alert_type="ARP_SPOOF_SUSPECTED",
                    severity="HIGH",
                    src_ip=src_ip,
                    details={
                        "reason": "ip_mac_conflict",
                        "src_ip": src_ip,
                        "new_mac": src_mac,
                        "known_macs": list(known_macs),
                    },
                ))
        known_macs.add(src_mac)

        # --- Condition 2: Gratuitous ARP flood ---
        if is_gratuitous:
            dq = self._gratuitous[src_mac]
            dq.append(ts)
            cutoff = ts - self.window_s
            while dq and dq[0] < cutoff:
                dq.popleft()

            count = len(dq)
            low_th = int(self.thresholds.get("low", max(1, self.threshold_gratuitous // 2)))

            if count >= low_th:
                default_low = low_th
                default_medium = int(self.thresholds.get("medium", self.threshold_gratuitous))
                default_high = int(self.thresholds.get("high", default_medium * 2))

                thresholds = normalize_thresholds(self.thresholds, default_low, default_medium, default_high)
                severity = classify(count, thresholds)

                if severity != "LOW":
                    fire_key = ("gratuitous", src_mac, severity)
                    if ts - self._last_fire[fire_key] >= self.INTERNAL_COOLDOWN_S:
                        self._last_fire[fire_key] = ts
                        alerts.append(Alert(
                            ts=ts,
                            alert_type="ARP_SPOOF_SUSPECTED",
                            severity=severity,
                            src_ip=src_ip,
                            details={
                                "reason": "gratuitous_arp_flood",
                                "src_mac": src_mac,
                                "window_s": self.window_s,
                                "count": count,
                                "thresholds": thresholds,
                            },
                        ))

        return alerts
