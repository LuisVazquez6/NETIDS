from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class Alert:
    ts : float
    alert_type: str
    severity: str
    src_ip: str
    details :dict[str, Any] = field(default_factory=dict)

    mitre_technique: Optional[str] = None

    dst_ip: Optional[str] = None
    proto: Optional[str] = None
    dst_port: Optional[int] = None
    sensor: str = "ids_victim"
    event_id: Optional[str] = None

