# src/response/notifier.py
from __future__ import annotations
from typing import Any, Dict, Tuple
import time
from collections import defaultdict

class Notifier:
    def __init__(self, cooldown_s: int = 20):
        self.cooldown_s = cooldown_s
        self.last_sent: Dict[str, float] = defaultdict(float)

    def _key(self, incident: Dict[str, Any]) -> str:
        return f"{incident.get('incident_id')}|{incident.get('severity')}|{incident.get('risk_score')}"

    def should_notify(self, incident: Dict[str, Any]) -> bool:
        k = self._key(incident)
        now = time.time()
        if now - self.last_sent[k] < self.cooldown_s:
            return False
        self.last_sent[k] = now
        return True

    def notify_console(self, incident: Dict[str, Any]) -> None:
        print(f"[INCIDENT] {incident.get('severity')} risk={incident.get('risk_score')} "
              f"id={incident.get('incident_id')} src={incident.get('primary_src_ip')} :: {incident.get('summary')}")