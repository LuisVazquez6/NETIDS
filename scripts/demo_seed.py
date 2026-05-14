#!/usr/bin/env python3
"""
Demo seed script — writes realistic multi-source alerts directly to logs/alerts.jsonl
so the dashboard shows 5 incidents from 5 countries without needing IP spoofing.

Usage:
  .venv/bin/python3 demo_seed.py           # append to existing alerts
  .venv/bin/python3 demo_seed.py --clear   # clear everything first, then seed
"""

import argparse
import hashlib
import json
import time
from pathlib import Path

ROOT        = Path(__file__).resolve().parents[1]   # project root (one level up from scripts/)
ALERTS_PATH = ROOT / "logs" / "alerts.jsonl"
VICTIM_IP   = "192.168.56.103"

ATTACKERS = [
    {
        "src_ip":      "185.220.101.45",
        "country":     "Germany",
        "country_code":"DE",
        "org":         "Tor Project / Zwiebelfreunde e.V.",
        "lat":         51.30,  "lon":  9.49,
        "reverse_dns": "tor-exit-45.example.de",
    },
    {
        "src_ip":      "45.33.32.156",
        "country":     "United States",
        "country_code":"US",
        "org":         "Linode LLC",
        "lat":         37.75,  "lon": -97.82,
        "reverse_dns": "",
    },
    {
        "src_ip":      "95.173.136.70",
        "country":     "Russia",
        "country_code":"RU",
        "org":         "Rostelecom",
        "lat":         55.75,  "lon":  37.62,
        "reverse_dns": "",
    },
    {
        "src_ip":      "116.228.112.26",
        "country":     "China",
        "country_code":"CN",
        "org":         "China Telecom Shanghai",
        "lat":         31.22,  "lon": 121.46,
        "reverse_dns": "",
    },
    {
        "src_ip":      "177.75.32.5",
        "country":     "Brazil",
        "country_code":"BR",
        "org":         "CLARO S.A.",
        "lat":        -15.78,  "lon": -47.93,
        "reverse_dns": "",
    },
]

MITRE_MAP = {
    "PORT_SCAN_SUSPECTED":          "T1046",
    "SYN_BURST_SUSPECTED":          "T1498",
    "ICMP_SWEEP_SUSPECTED":         "T1018",
    "LATERAL_MOVEMENT_SUSPECTED":   "T1021",
    "DNS_TUNNEL_SUSPECTED":         "T1071.004",
    "WEB_EXPLOIT_SUSPECTED":        "T1190",
    "SLOW_LORIS_SUSPECTED":         "T1499",
}

DST_SERVICES = {22: "ssh", 53: "dns", 80: "http", 443: "https", 8080: "http-alt"}


def _fp(alert_type, src_ip, ts):
    return hashlib.sha1(f"{alert_type}|{src_ip}|{ts}".encode()).hexdigest()[:12]


def make_alert(attacker, alert_type, severity, ts, dst_port, proto, details):
    return {
        "alert_type":      alert_type,
        "severity":        severity,
        "src_ip":          attacker["src_ip"],
        "dst_ip":          VICTIM_IP,
        "dst_port":        dst_port,
        "proto":           proto,
        "ts":              round(ts, 3),
        "event_id":        _fp(alert_type, attacker["src_ip"], ts),
        "mitre_technique": MITRE_MAP.get(alert_type, "UNKNOWN"),
        "enrichment": {
            "src_is_private":   False,
            "src_reverse_dns":  attacker.get("reverse_dns", ""),
            "src_country":      attacker["country"],
            "src_country_code": attacker["country_code"],
            "src_org":          attacker["org"],
            "src_lat":          attacker["lat"],
            "src_lon":          attacker["lon"],
            "dst_service":      DST_SERVICES.get(dst_port, ""),
        },
        "details": details,
    }


def build_alerts(now):
    DE, US, RU, CN, BR = ATTACKERS
    alerts = []

    def add(attacker, alert_type, severity, offset, dst_port, proto, details):
        alerts.append(
            make_alert(attacker, alert_type, severity, now - offset, dst_port, proto, details)
        )

    # ── Germany (Tor exit) — ICMP Sweep → Port Scan → SYN Flood ─────────────
    add(DE, "ICMP_SWEEP_SUSPECTED",  "MEDIUM", 480, None, "ICMP", {"unique_hosts": 12, "sample_targets": ["192.168.56.1","192.168.56.2","192.168.56.3"], "window_s": 30})
    add(DE, "ICMP_SWEEP_SUSPECTED",  "HIGH",   450, None, "ICMP", {"unique_hosts": 32, "sample_targets": ["192.168.56.1","192.168.56.5","192.168.56.10"], "window_s": 30})
    add(DE, "PORT_SCAN_SUSPECTED",   "MEDIUM", 420, 80,   "TCP",  {"distinct_ports": 28, "window_s": 15})
    add(DE, "PORT_SCAN_SUSPECTED",   "HIGH",   390, 443,  "TCP",  {"distinct_ports": 65, "window_s": 15})
    add(DE, "SYN_BURST_SUSPECTED",   "MEDIUM", 360, 80,   "TCP",  {"syn_count": 15, "window_s": 8})
    add(DE, "SYN_BURST_SUSPECTED",   "HIGH",   330, 80,   "TCP",  {"syn_count": 58, "window_s": 8})

    # ── United States (Linode VPS) — Lateral Movement ────────────────────────
    add(US, "LATERAL_MOVEMENT_SUSPECTED", "MEDIUM", 310, 22, "TCP", {"unique_hosts": 9,  "admin_ports": ["SSH"], "sample_targets": ["192.168.56.1","192.168.56.2","192.168.56.4"], "window_s": 60})
    add(US, "LATERAL_MOVEMENT_SUSPECTED", "HIGH",   270, 22, "TCP", {"unique_hosts": 21, "admin_ports": ["SSH","RDP"], "sample_targets": ["192.168.56.1","192.168.56.3","192.168.56.7"], "window_s": 60})

    # ── Russia (Rostelecom) — DNS Tunneling ──────────────────────────────────
    add(RU, "DNS_TUNNEL_SUSPECTED",  "MEDIUM", 250, 53, "UDP/DNS", {"query_count": 44, "window_s": 10})
    add(RU, "DNS_TUNNEL_SUSPECTED",  "HIGH",   210, 53, "UDP/DNS", {"query_count": 88, "max_label_len": 78, "window_s": 10})

    # ── China (China Telecom) — Web Exploit ──────────────────────────────────
    add(CN, "WEB_EXPLOIT_SUSPECTED", "HIGH",   190, 5000, "TCP", {"pattern_type": "SQL_INJECTION",  "matched": "' OR '1'='1", "uri": "/login"})
    add(CN, "WEB_EXPLOIT_SUSPECTED", "MEDIUM", 160, 5000, "TCP", {"pattern_type": "PATH_TRAVERSAL", "matched": "../../../../etc/passwd", "uri": "/login?file=../../../../etc/passwd"})
    add(CN, "WEB_EXPLOIT_SUSPECTED", "HIGH",   130, 5000, "TCP", {"pattern_type": "CMD_INJECTION",  "matched": "; cat /etc/shadow", "uri": "/admin?cmd=;+cat+/etc/shadow"})

    # ── Brazil (Claro) — Slow Loris ──────────────────────────────────────────
    add(BR, "SLOW_LORIS_SUSPECTED",  "MEDIUM", 100, 80, "TCP", {"half_open_connections": 23})
    add(BR, "SLOW_LORIS_SUSPECTED",  "HIGH",    45, 80, "TCP", {"half_open_connections": 47})

    alerts.sort(key=lambda a: a["ts"])
    return alerts


SEV_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m"}
RESET = "\033[0m"
BOLD  = "\033[1m"
CYAN  = "\033[96m"

FLAG = {"DE": "🇩🇪", "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳", "BR": "🇧🇷"}


def main():
    parser = argparse.ArgumentParser(description="NetIDS demo seed — populates dashboard with 5-country attack data")
    parser.add_argument("--clear", action="store_true", help="Clear alerts.jsonl before seeding")
    args = parser.parse_args()

    ALERTS_PATH.parent.mkdir(parents=True, exist_ok=True)

    if args.clear:
        ALERTS_PATH.write_text("", encoding="utf-8")
        triage = ROOT / "logs" / "triage.jsonl"
        cleared = ROOT / "logs" / "cleared_incidents.json"
        try:
            if triage.exists():
                triage.write_text("", encoding="utf-8")
        except PermissionError:
            print(f"{CYAN}[!] triage.jsonl is root-owned — fix with: sudo chown ids-victim:ids-victim logs/triage.jsonl{RESET}")
            print(f"{CYAN}    (continuing — old triage entries will persist but won't break the demo){RESET}")
        if cleared.exists():
            cleared.unlink()
        print(f"{CYAN}[*] Cleared alerts and incidents{RESET}")

    now = time.time()
    alerts = build_alerts(now)

    print(f"\n{BOLD}NetIDS Demo Seed{RESET} — injecting {len(alerts)} alerts\n")

    with ALERTS_PATH.open("a", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
            sev  = a["severity"]
            src  = a["src_ip"]
            code = a["enrichment"]["src_country_code"]
            country = a["enrichment"]["src_country"]
            atype = a["alert_type"].replace("_", " ")
            c = SEV_COLOR.get(sev, "")
            print(f"  {c}[{sev}]{RESET} {FLAG.get(code,'')} {BOLD}{src}{RESET} ({country}) — {atype}")

    print(f"\n{CYAN}[+] Done — refresh the dashboard to see 5 incidents from 5 countries{RESET}\n")


if __name__ == "__main__":
    main()
