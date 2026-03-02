# src/models/incident.py
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import time
import uuid

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}

def severity_max(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.get(a, 0) >= SEVERITY_ORDER.get(b, 0) else b

@dataclass
class Incident:
    incident_id: str
    status: str  # OPEN | INVESTIGATING | CONTAINED | CLOSED
    severity: str  # LOW | MEDIUM | HIGH
    risk_score: int  # 0-100
    primary_src_ip: str
    entities: Dict[str, Any] = field(default_factory=dict)

    first_seen: float = field(default_factory=lambda: time.time())
    last_seen: float = field(default_factory=lambda: time.time())

    alert_count: int = 0
    alert_types: Dict[str, int] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)

    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def new_incident_id() -> str:
    return uuid.uuid4().hex[:12]