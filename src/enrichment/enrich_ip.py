# src/enrichment/enrich_ip.py
from __future__ import annotations
from typing import Any, Dict
import ipaddress
import socket

KNOWN_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    53: "dns",
    3389: "rdp",
    445: "smb",
    139: "netbios",
}

def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""

def enrich_alert_dict(alert: Dict[str, Any]) -> Dict[str, Any]:
    # expected alert keys: src_ip, details{dst_ip?, dst_port?}
    src = alert.get("src_ip", "")
    details = alert.get("details", {}) or {}

    dst_port = details.get("dst_port")
    service = KNOWN_SERVICES.get(dst_port, "") if isinstance(dst_port, int) else ""

    alert.setdefault("enrichment", {})
    alert["enrichment"].update({
        "src_is_private": is_private(src),
        "src_reverse_dns": reverse_dns(src) if src else "",
        "dst_service": service,
    })
    return alert