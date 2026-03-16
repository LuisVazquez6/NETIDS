from __future__ import annotations

from typing import Any, Dict, Optional
import json
import time 
from collections import defaultdict
import urllib.request

_SEV_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

class Notifier:
    def __init__(
        self,
        cooldown_s: int = 20,
        min_severity: str = "MEDIUM",
        webhook_url: Optional[str] = None,
    ):

        self.cooldown_s = cooldown_s
        self.min_severity = min_severity
        self.webhook_url = webhook_url
        self.last_sent: Dict[str, float] = defaultdict(float)

    def _sev_ok(self, incident: Dict[str, Any]) -> bool:
        sev = str(incident.get("severity", "LOW"))
        return _SEV_ORDER.get(sev,0) >= _SEV_ORDER.get(self.min_severity, 1)

    def _key(self, incident: Dict[str, Any]) -> str:
        inc_id = incident.get("incident_id") or incident.get("id") or "unknow"
        src = incident.get("primary_src_ip") or incident.get("src_ip") or "unknow"
        sev = incident.get("severity") or "LOW"
        return f"{inc_id}|{src}|{sev}"

    def should_notify(self, incident: Dict[str, Any]) -> bool:
        if not self._sev_ok(incident):
            return False
        
        k = self._key(incident)
        now = time.time()
        if now - self.last_sent[k] < self.cooldown_s:
            return False
        self.last_sent[k] = now
        return True

    def notify_console(self, incident: Dict[str, Any]) -> None:
        sev   = incident.get("severity", "LOW")
        color = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}.get(sev, "\033[0m")
        reset = "\033[0m"
        bold  = "\033[1m"
        print(
            f"\n{color}{bold}[INCIDENT]{reset} {color}{sev}{reset}"
            f" risk={bold}{incident.get('risk_score')}{reset}"
            f" id={incident.get('incident_id')}"
            f" src={bold}{incident.get('primary_src_ip')}{reset}"
            f" :: {incident.get('summary')}"
        )

    def notify_webhook(self, incident: Dict[str, Any]) -> None:
        if not self.webhook_url:
            return 

        msg =(
            f"incident severity={incident.get('severity')} "
            f"risk={incident.get('risk_score')} "
            f"id={incident.get('incident_id')} "
            f"src={incident.get('primary_src_ip')} "
            f"summary={incident.get('summary')}"
        )

        payload = {"content": msg, "text": msg}
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type":"application/json"},
            method = "POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()