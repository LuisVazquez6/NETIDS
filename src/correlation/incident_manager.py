# src/correlation/incident_manager.py
from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
import time
from collections import defaultdict

from models.incidents import Incident, new_incident_id, severity_max, SEVERITY_ORDER

# Basic SOC-style weights (tune anytime)
ALERT_WEIGHTS = {
    "PORT_SCAN_SUSPECTED": 30,
    "SYN_BURST_SUSPECTED": 35,
    "ICMP_FLOOD_SUSPECTED": 25,
    "ICMP_SWEEP_SUSPECTED": 20,
    "SSH_BRUTEFORCE_SUSPECTED": 40,
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
    "SSH_BRUTEFORCE_SUSPECTED": [
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

    def _is_duplicate(self, inc: Incident, alert_type: str, severity: str) -> bool:
        """Return True if this alert_type has already been seen at this severity or higher."""
        seen_sev = inc.alert_severities.get(alert_type)
        if seen_sev is None:
            return False
        return SEVERITY_ORDER.get(seen_sev, 0) >= SEVERITY_ORDER.get(severity, 0)

    def ingest(self, alert: Dict[str, Any]) -> Tuple[Incident, bool, bool]:
        """
        Returns (incident, is_new_incident, escalated).

        Duplicate suppression: an alert is silently dropped when the same
        alert_type has already been recorded at the same or higher severity
        within the current incident window.

        Severity escalation: an alert is accepted (and escalated=True is
        returned) when its severity is strictly higher than what was
        previously seen for that alert_type, or when the incident's overall
        severity is promoted.
        """
        now = float(alert.get("ts", time.time()))
        src = alert.get("src_ip", "unknown")
        atype = alert.get("alert_type", "UNKNOWN")
        new_sev = alert.get("severity", "LOW")

        # expire stale incidents (idle)
        self._expire(now)

        inc = self.open_by_src.get(src)
        is_new = False
        if inc is None or (now - inc.last_seen) > self.window_s:
            is_new = True
            inc = Incident(
                incident_id=new_incident_id(),
                status="OPEN",
                severity=new_sev,
                risk_score=0,
                primary_src_ip=src,
                entities={"src_ip": src},
                first_seen=now,
                last_seen=now,
            )
            self.open_by_src[src] = inc

        # --- duplicate suppression ---
        if not is_new and self._is_duplicate(inc, atype, new_sev):
            # Same alert_type at same/lower severity — touch timestamp but skip
            inc.last_seen = now
            self.last_touch[src] = now
            return inc, False, False

        # --- accept the alert ---
        prev_incident_severity = inc.severity

        inc.last_seen = now
        inc.alert_count += 1
        inc.alert_types[atype] = inc.alert_types.get(atype, 0) + 1

        # Record highest severity seen per alert_type
        inc.alert_severities[atype] = severity_max(
            inc.alert_severities.get(atype, "LOW"), new_sev
        )

        inc.severity = severity_max(inc.severity, new_sev)
        escalated = (not is_new) and (inc.severity != prev_incident_severity)

        # risk score: max of per-alert score, slightly grows with volume
        inc.risk_score = min(100, max(inc.risk_score, self._score(alert)) + (1 if inc.alert_count % 5 == 0 else 0))

        # timeline entry
        inc.timeline.append({
            "ts": now,
            "alert_type": atype,
            "severity": new_sev,
            "details": alert.get("details", {}),
        })

        # recommendations
        self._merge_recommendations(inc, atype)

        # summary
        self._update_summary(inc)

        self.last_touch[src] = now
        return inc, is_new, escalated

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