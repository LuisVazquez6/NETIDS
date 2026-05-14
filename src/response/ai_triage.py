from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

_ROOT = Path(__file__).resolve().parents[2]
_TRIAGE_PATH = _ROOT / "logs" / "triage.jsonl"
_TRIAGE_LOCK = threading.Lock()

_client = None


def _get_client():
    global _client
    if _client is not None:
        return _client
    try:
        import anthropic
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not key or key.startswith("paste-"):
            return None
        _client = anthropic.Anthropic(api_key=key)
        return _client
    except Exception:
        return None


def _build_prompt(incident: Dict[str, Any]) -> str:
    src = incident.get("primary_src_ip") or incident.get("src_ip", "unknown")
    severity = incident.get("severity", "LOW")
    risk = incident.get("risk_score", 0)
    summary = incident.get("summary", "")
    chain = incident.get("attack_chain", "")

    alert_types = incident.get("alert_types", {})
    if isinstance(alert_types, dict):
        types_str = ", ".join(f"{t} x{c}" for t, c in alert_types.items())
    else:
        types_str = str(alert_types)

    timeline = incident.get("timeline", [])
    timeline_str = ""
    if timeline:
        for entry in timeline[-5:]:
            ts = entry.get("ts", 0)
            try:
                t = datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")
            except Exception:
                t = "?"
            timeline_str += f"  {t} — {entry.get('alert_type','')} [{entry.get('severity','')}]\n"

    enrichment = incident.get("enrichment", {}) or {}
    country = enrichment.get("src_country", "")
    org = enrichment.get("src_org", "")
    geo = f"{country} / {org}".strip(" /") if (country or org) else "unknown"

    return f"""You are a SOC analyst reviewing a network intrusion detection alert. Respond concisely.

INCIDENT SUMMARY
  Source IP   : {src}
  GeoIP       : {geo}
  Severity    : {severity}
  Risk Score  : {risk}/100
  Alert types : {types_str}
  Attack chain: {chain or "none detected"}
  Summary     : {summary}

RECENT TIMELINE
{timeline_str or "  (no timeline)"}

Respond in exactly this format (no extra text):
ATTACK: <one-line attack classification>
ANALYSIS: <2-3 sentences explaining what the attacker is doing and their likely goal>
RESPONSE: <2-3 short bullet points the SOC team should do right now>"""


def _write_triage(incident_id: str, src_ip: str, alert_type: str, severity: str, ts: float, result: str, status: str) -> None:
    entry = {
        "incident_id": incident_id,
        "src_ip":      src_ip,
        "alert_type":  alert_type,
        "severity":    severity,
        "ts":          ts,
        "triage":      result,
        "status":      status,
        "triage_ts":   time.time(),
    }
    # Dedup key: one triage entry per (src_ip, alert_type)
    dedup_key = f"{src_ip}|{alert_type}"
    _TRIAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _TRIAGE_LOCK:
        existing = []
        updated = False
        if _TRIAGE_PATH.exists():
            for line in _TRIAGE_PATH.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    obj_key = f"{obj.get('src_ip')}|{obj.get('alert_type','')}"
                    if obj_key == dedup_key:
                        existing.append(json.dumps(entry))
                        updated = True
                    else:
                        existing.append(line)
                except Exception:
                    existing.append(line)
        if not updated:
            existing.append(json.dumps(entry))
        content = "\n".join(existing) + "\n"
        try:
            _TRIAGE_PATH.write_text(content, encoding="utf-8")
        except PermissionError:
            _TRIAGE_PATH.unlink(missing_ok=True)
            _TRIAGE_PATH.write_text(content, encoding="utf-8")
        try:
            os.chmod(_TRIAGE_PATH, 0o664)
        except PermissionError:
            pass


def analyze_async(incident: Dict[str, Any]) -> None:
    """Spawn a background thread to triage an incident via Claude Haiku."""
    t = threading.Thread(target=_analyze, args=(incident,), daemon=True)
    t.start()


def _analyze(incident: Dict[str, Any]) -> None:
    incident_id = incident.get("incident_id", "unknown")
    src_ip      = incident.get("primary_src_ip") or incident.get("src_ip", "unknown")
    severity    = incident.get("severity", "LOW")
    ts          = incident.get("first_seen", time.time())
    # Use alert_type_key if set (per-type incidents), else derive from alert_types dict
    alert_type = incident.get("alert_type_key", "")
    if not alert_type:
        types = incident.get("alert_types", {})
        if isinstance(types, dict) and types:
            alert_type = max(types.items(), key=lambda x: x[1])[0]
        elif isinstance(types, list) and types:
            alert_type = types[0].get("type", "UNKNOWN")

    client = _get_client()
    if client is None:
        _write_triage(incident_id, src_ip, alert_type, severity, ts,
                      "AI triage unavailable — check ANTHROPIC_API_KEY in .env", "error")
        return

    try:
        prompt = _build_prompt(incident)
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}],
        )
        result = message.content[0].text.strip()
        _write_triage(incident_id, src_ip, alert_type, severity, ts, result, "done")
        print(f"\033[96m[AI TRIAGE]\033[0m {src_ip} {alert_type} → {result.splitlines()[0]}")
    except Exception as e:
        _write_triage(incident_id, src_ip, alert_type, severity, ts, f"Triage error: {e}", "error")
