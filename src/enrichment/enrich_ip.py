# src/enrichment/enrich_ip.py
from __future__ import annotations
from typing import Any, Dict, Optional
import ipaddress
import socket
import urllib.request
import urllib.error
import json

KNOWN_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    53: "dns",
    3389: "rdp",
    445: "smb",
    139: "netbios",
}

# Simple in-process cache so each IP is only looked up once per run
_geo_cache: Dict[str, Dict[str, str]] = {}

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

def geoip_lookup(ip: str) -> Dict[str, str]:
    """
    Returns country, org (ASN) for the IP using ip-api.com (free, no key).
    Private/reserved IPs are skipped and return empty strings.
    """
    if ip in _geo_cache:
        return _geo_cache[ip]

    empty = {"country": "", "country_code": "", "org": ""}

    if is_private(ip):
        _geo_cache[ip] = empty
        return empty

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,org"
        req = urllib.request.Request(url, headers={"User-Agent": "netids/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            result = {
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "org":          data.get("org", ""),
            }
        else:
            result = empty
    except Exception:
        result = empty

    _geo_cache[ip] = result
    return result

def enrich_alert_dict(alert: Dict[str, Any]) -> Dict[str, Any]:
    src = alert.get("src_ip", "")
    details = alert.get("details", {}) or {}

    dst_port = alert.get("dst_port") or details.get("dst_port")
    service = KNOWN_SERVICES.get(dst_port, "") if isinstance(dst_port, int) else ""

    geo = geoip_lookup(src) if src else {}

    alert.setdefault("enrichment", {})
    alert["enrichment"].update({
        "src_is_private":  is_private(src),
        "src_reverse_dns": reverse_dns(src) if src else "",
        "dst_service":     service,
        "src_country":     geo.get("country", ""),
        "src_country_code": geo.get("country_code", ""),
        "src_org":         geo.get("org", ""),
    })
    return alert