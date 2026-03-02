# src/correlation/incident_manager.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import time
from collections import defaultdict

from models.incidents import Incident, new_incident_id, severity_max

# Basic SOC-style weights (tune anytime)
ALERT_WEIGHTS = {
    "PORT_SCAN_SUSPECTED": 30,
    "SYN_BURST_SUSPECTED": 35,
    "ICMP_FLOOD_SUSPECTED": 25,
    "ICMP_SWEEP_SUSPECTED": 20,
    "SSH_BRUTE_FORCE_SUSPECTED": 40,
}

SEVERITY_WEIGHT = {"LOW": 10, "MEDIUM": 20, "HIGH": 35}

DEFAULT_RECS = {
    "PORT_SCAN_SUSPECTED": [
        "Confirm if source is authorized scanner.",
        "Block or rate-limit source if unauthorized.",
        "Review exposed services and close unused ports.",
    ],
    "SYN_BURST_SUSPECTED": [
        "Check for SYN flood symptoms (CPU/conn backlog).",
        "Enable SYN cookies / rate limiting if applicable.",
        "Block source if malicious.",
    ],
    "SSH_BRUTE_FORCE_SUSPECTED": [
        "Check auth logs for failed logins.",
        "Enforce key-based auth and disable password auth.",
        "Consider blocking source and rotating credentials.",
    ],
    "ICMP_FLOOD_SUSPECTED": [
        "Rate-limit ICMP at firewall.",
        "Validate monitoring systems aren’t the source.",
    ],
    "ICMP_SWEEP_SUSPECTED": [
        "Confirm if discovery scan is authorized.",
        "Investigate lateral movement attempts.",
    ],
}

class IncidentManager:
    """
    Groups alerts into incidents by (src_ip) within a time window.
    You can later expand this to include dst_ip, tactic, etc.
    """

    def __init__(self, window_s: int = 120, max_idle_s: int = 300):
        self.window_s = window_s
        self.max_idle_s = max_idle_s
        self.open_by_src: Dict[str, Incident] = {}
        self.last_touch: Dict[str, float] = defaultdict(float)

    def _score(self, alert: Dict[str, Any]) -> int:
        atype = alert.get("alert_type", "")
        sev = alert.get("severity", "LOW")
        base = ALERT_WEIGHTS.get(atype, 15)
        sev_w = SEVERITY_WEIGHT.get(sev, 10)
        return min(100, base + sev_w)

    def _update_summary(self, inc: Incident) -> None:
        top_types = sorted(inc.alert_types.items(), key=lambda x: x[1], reverse=True)
        top_str = ", ".join([f"{t}({c})" for t, c in top_types[:3]])
        inc.summary = f"{inc.primary_src_ip} triggered {inc.alert_count} alerts: {top_str}"

    def _merge_recommendations(self, inc: Incident, alert_type: str) -> None:
        for r in DEFAULT_RECS.get(alert_type, []):
            if r not in inc.recommendations:
                inc.recommendations.append(r)

    def ingest(self, alert: Dict[str, Any]) -> Tuple[Incident, bool]:
        """
        Returns (incident, is_new_incident)
        """
        now = float(alert.get("ts", time.time()))
        src = alert.get("src_ip", "unknown")

        # expire stale incidents (idle)
        self._expire(now)

        inc = self.open_by_src.get(src)
        is_new = False
        if inc is None or (now - inc.last_seen) > self.window_s:
            is_new = True
            inc = Incident(
                incident_id=new_incident_id(),
                status="OPEN",
                severity=alert.get("severity", "LOW"),
                risk_score=0,
                primary_src_ip=src,
                entities={"src_ip": src},
                first_seen=now,
                last_seen=now,
            )
            self.open_by_src[src] = inc

        # update incident fields
        inc.last_seen = now
        inc.alert_count += 1

        atype = alert.get("alert_type", "UNKNOWN")
        inc.alert_types[atype] = inc.alert_types.get(atype, 0) + 1

        inc.severity = severity_max(inc.severity, alert.get("severity", "LOW"))

        # risk score: max of per-alert score, slightly grows with volume
        inc.risk_score = min(100, max(inc.risk_score, self._score(alert)) + (1 if inc.alert_count % 5 == 0 else 0))

        # timeline entry
        inc.timeline.append({
            "ts": now,
            "alert_type": atype,
            "severity": alert.get("severity", "LOW"),
            "details": alert.get("details", {}),
        })

        # recommendations
        self._merge_recommendations(inc, atype)

        # summary
        self._update_summary(inc)

        self.last_touch[src] = now
        return inc, is_new

    def _expire(self, now: float) -> None:
        stale = []
        for src, ts in list(self.last_touch.items()):
            if now - ts > self.max_idle_s:
                stale.append(src)
        for src in stale:
            self.open_by_src.pop(src, None)
            self.last_touch.pop(src, None)

    def list_open(self) -> List[Incident]:
        return list(self.open_by_src.values())