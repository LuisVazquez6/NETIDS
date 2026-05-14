# NetIDS — Network Intrusion Detection System

> A Python/Scapy IDS that detects real-time attack traffic using rolling time-window thresholds, with AI-powered triage, GeoIP enrichment, MITRE ATT&CK mapping, and a live SOC-style web dashboard.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.7-green?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
![Claude](https://img.shields.io/badge/Claude-Haiku-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard](#dashboard)
- [AI Triage](#ai-triage)
- [Alert Format](#alert-format)
- [Detection Thresholds](#detection-thresholds)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Demo](#demo)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)

---

## Overview

NetIDS is a Network Intrusion Detection System built with Python and Scapy. It supports two operation modes:

- **Live Mode** — Sniffs packets directly from a network interface in real time via Scapy's `sniff()` loop
- **PCAP Mode** — Analyzes pre-captured `.pcap`/`.pcapng` files for offline forensic investigation

Detection is based on rolling time-window counters with configurable LOW / MEDIUM / HIGH severity thresholds. Alerts escalate automatically as traffic intensity grows — a source that starts at MEDIUM will trigger a separate HIGH alert once it crosses the next threshold. All alerts are written in **JSON Lines** format for easy SIEM integration.

A Flask SOC dashboard provides real-time visibility: live alert feed, geo attack map, incident correlation, and automated AI triage powered by **Claude Haiku**.

---

## Features

| Feature | Description |
|---|---|
| **TCP Port Scan Detection** | Tracks unique destination ports per source IP in a rolling window |
| **SYN Burst / SYN Flood Detection** | Detects DoS-indicative SYN packet bursts from a single source |
| **ICMP Sweep Detection** | Identifies high-rate ICMP echo requests indicative of host discovery |
| **Lateral Movement Detection** | Flags SSH SYN probes targeting many hosts from one source |
| **DNS Tunneling Detection** | Flags high-rate or oversized DNS queries indicative of data exfiltration |
| **Web Exploit Detection** | Detects SQL injection, path traversal, and command injection patterns |
| **Slow Loris Detection** | Identifies large numbers of half-open TCP connections targeting a web server |
| **3-Level Severity Escalation** | Each detector emits LOW → MEDIUM → HIGH as attack intensity grows |
| **IP Enrichment** | Reverse DNS, private-IP detection, country, and ASN lookups per alert |
| **MITRE ATT&CK Mapping** | Every alert type is mapped to a MITRE technique ID |
| **Incident Correlation** | Alerts from the same source IP are grouped into incidents with a 0–100 risk score |
| **Attack Chain Detection** | Recognizes multi-stage campaigns (e.g. Recon → Lateral Movement) |
| **AI Triage** | Claude Haiku analyzes each incident and returns attack classification, analysis, and recommended response |
| **IP Whitelist** | Suppress alerts from trusted internal addresses via `config.json` |
| **Auto-Block** | Optional `--auto-block` flag drops HIGH-severity sources via `iptables` (requires root) |
| **JSON Lines Alert Logging** | Structured, timestamped alerts ready for any SIEM pipeline |
| **SOC Dashboard** | Password-protected web UI with live alert feed, geo map, AI triage, and IDS engine control |

---

## Architecture

```
NIC (live)  ──┐
               ├──► ids.py (packet router)
PCAP file  ──┘         │
                        │ per packet
                        ▼
              ┌─────────────────────────────────┐
              │         Detection Layer          │
              │  port_scan · syn_burst           │
              │  icmp_sweep · lateral_movement   │
              │  dns_tunnel · web_exploit        │
              │  slow_loris                      │
              └──────────────┬──────────────────┘
                             │ Alert objects
                             ▼
              enrich_ip · mitre_mapper (enrichment)
                             │
                             ▼
              60s alert deduplication (in ids.py)
                             │
                             ▼
              IncidentManager (120s window, risk 0–100)
                             │
                  ┌──────────┴────────────┐
                  ▼                       ▼
            Console output          alerts.jsonl
            (color-coded)        (logs/ directory)
                                         │
                                         ▼
                           Flask dashboard (port 5000)
                                         │
                              ┌──────────┴──────────┐
                              ▼                     ▼
                        AI Triage              Attack Map
                     (Claude Haiku)          (Leaflet.js)
```

### Layer breakdown

| Layer | Files | Responsibility |
|---|---|---|
| **Input** | `src/ids.py` | Starts Scapy sniff loop or reads PCAP; routes raw packets to detectors |
| **Detection** | `src/rules/` | Per-packet evaluation against rolling time-window thresholds; 3 severity levels |
| **Enrichment** | `src/enrichment/` | Adds reverse DNS, country/ASN data; maps alert types to MITRE ATT&CK technique IDs |
| **Correlation** | `src/correlation/incident_manager.py` | Groups alerts by `src_ip` in a 120s window; computes 0–100 risk score; detects attack chains |
| **Response** | `src/response/notifier.py`, `src/response/ai_triage.py` | Console output; webhook notifications; Claude Haiku AI triage |
| **Dashboard** | `src/dashboard/flask_app.py` | Password-protected Flask UI; reads `logs/alerts.jsonl` in real time |

---

## Installation

```bash
git clone https://github.com/LuisVazquez6/NETIDS.git
cd NETIDS

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install anthropic
```

### API Key setup (required for AI triage)

Create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Both `run_ids.sh` and `run_dashboard.sh` load this file automatically. Without it the dashboard still works — AI triage will show a warning instead of analysis.

> **Note:** Live packet capture requires root/administrator privileges (`sudo`).

---

## Usage

### Live capture mode

```bash
# Using the helper script (runs on enp0s3 by default)
sudo bash run_ids.sh

# Or directly
sudo .venv/bin/python3 src/ids.py --live --iface enp0s3
```

### PCAP analysis mode

```bash
.venv/bin/python3 src/ids.py --pcap capture.pcap
```

### All CLI options

```
--live                  Sniff live packets
--iface IFACE           Network interface (default: system default)
--pcap FILE             Path to .pcap or .pcapng file
--log PATH              Alert output path (default: logs/alerts.jsonl)
--config PATH           Config file path (default: config.json)
--auto-block            Auto-block HIGH severity sources via iptables (root required)
```

---

## Dashboard

```bash
bash run_dashboard.sh
```

Opens at `http://<host>:5000`. Login credentials are set in `config.json` (default: `admin` / `netids2025`).

### Dashboard panels

| Panel | Description |
|---|---|
| **Stat Cards** | Total alerts, HIGH / MEDIUM / LOW counts, and live alerts-per-minute rate |
| **IDS Engine Control** | Start and stop the live IDS directly from the browser; shows per-detector alert counts and uptime |
| **Severity Chart** | Doughnut chart of alert distribution by severity |
| **Alert Timeline** | Bar chart of alert volume by hour |
| **Top Attackers** | Bar chart of the top 5 source IPs by alert count |
| **Live Attack Map** | Leaflet.js world map with geo-located attack markers colored by severity |
| **Active Incidents** | Collapsible incident cards grouped by source IP and attack type; click to load AI triage |
| **Live Alert Feed** | Scrollable feed of every individual alert with severity badge, MITRE ID, source IP, and resolve button |

### Audio alerts

The dashboard plays an audible alert tone when new HIGH or MEDIUM severity alerts arrive — no setup required, uses the browser's Web Audio API.

### Load Demo Data

The **⚡ LOAD DEMO DATA** button in the IDS Engine Control panel seeds the dashboard with 23 realistic alerts from 5 countries (Germany, US, Russia, China, Brazil) covering all 7 attack types and all 3 severity levels — no network traffic or hping3 required.

---

## AI Triage

When an incident card is clicked, NetIDS triggers an asynchronous Claude Haiku analysis of that incident. The triage result appears inline and includes:

- **ATTACK** — one-line classification of the attack type and likely threat actor goal
- **ANALYSIS** — 2–3 sentences explaining what the attacker is doing
- **RESPONSE** — 2–3 bullet-point actions for the SOC team

Triage results are cached in `logs/triage.jsonl` so they persist across page refreshes and are not re-requested on every poll.

---

## Alert Format

Alerts are written to `logs/alerts.jsonl` — one JSON object per line:

```json
{
  "alert_type": "PORT_SCAN_SUSPECTED",
  "severity": "MEDIUM",
  "src_ip": "185.220.101.45",
  "dst_ip": "192.168.56.103",
  "dst_port": 443,
  "proto": "TCP",
  "ts": 1748000000.0,
  "event_id": "a3f9c12b4d7e",
  "mitre_technique": "T1046",
  "enrichment": {
    "src_is_private": false,
    "src_reverse_dns": "tor-exit-45.example.de",
    "src_country": "Germany",
    "src_country_code": "DE",
    "src_org": "Tor Project",
    "src_lat": 51.3,
    "src_lon": 9.49,
    "dst_service": "https"
  },
  "details": {
    "distinct_ports": 38,
    "window_s": 15,
    "thresholds": {"low": 15, "medium": 30, "high": 60}
  }
}
```

| Field | Description |
|---|---|
| `alert_type` | Detection type (e.g. `PORT_SCAN_SUSPECTED`, `SYN_BURST_SUSPECTED`) |
| `severity` | `LOW`, `MEDIUM`, or `HIGH` |
| `src_ip` | Source IP that triggered the alert |
| `dst_ip` / `dst_port` | Destination address and port |
| `proto` | Protocol (`TCP`, `UDP/DNS`, `ICMP`) |
| `ts` | Unix timestamp of alert |
| `event_id` | Short SHA-1 fingerprint for deduplication |
| `mitre_technique` | MITRE ATT&CK technique ID |
| `enrichment` | Reverse DNS, private flag, country, org/ASN, geo coordinates, dst service |
| `details` | Detector-specific counters and thresholds |

---

## Detection Thresholds

All thresholds are configurable in `config.json`. Each detector tracks events in a sliding time window and escalates severity as counts grow.

| Detector | Window | LOW | MEDIUM | HIGH | Trigger condition |
|---|---|---|---|---|---|
| TCP Port Scan | 15s | 15 ports | 30 ports | 60 ports | Unique dst ports from one src |
| SYN Burst | 8s | 8 pkts | 12 pkts | 50 pkts | SYN-only packets from one src |
| ICMP Sweep | 30s | 5 pkts | 10 pkts | 30 pkts | ICMP echo requests from one src |
| Lateral Movement | 60s | 4 hosts | 8 hosts | 20 hosts | SSH SYN probes to unique hosts |
| DNS Tunneling | 10s | 20 queries | 40 queries | 80 queries | DNS queries from one src (or oversized labels) |
| Web Exploit | — | — | pattern | pattern | SQL injection, path traversal, cmd injection in HTTP |
| Slow Loris | — | 10 conns | 20 conns | 40 conns | Half-open TCP connections from one src |

> LOW severity alerts are written to the log but filtered from the live feed by default. MEDIUM and HIGH trigger notifications and AI triage.

---

## MITRE ATT&CK Mapping

| Alert Type | Technique | Tactic |
|---|---|---|
| `PORT_SCAN_SUSPECTED` | T1046 — Network Service Discovery | Reconnaissance |
| `SYN_BURST_SUSPECTED` | T1498 — Network Denial of Service | Impact |
| `ICMP_SWEEP_SUSPECTED` | T1018 — Remote System Discovery | Reconnaissance |
| `LATERAL_MOVEMENT_SUSPECTED` | T1021 — Remote Services | Lateral Movement |
| `DNS_TUNNEL_SUSPECTED` | T1071.004 — Application Layer Protocol: DNS | Command & Control |
| `WEB_EXPLOIT_SUSPECTED` | T1190 — Exploit Public-Facing Application | Initial Access |
| `SLOW_LORIS_SUSPECTED` | T1499 — Endpoint Denial of Service | Impact |

---

## Demo

### Demo seed (no network required)

Instantly populates the dashboard with 23 pre-built alerts from 5 countries across all 7 attack types and all 3 severity levels:

```bash
.venv/bin/python3 scripts/demo_seed.py --clear
```

Or click **⚡ LOAD DEMO DATA** in the dashboard.

### Demo attack script (live traffic)

`scripts/demo_attack.sh` runs a 7-stage simulated attack sequence from a Kali machine against the IDS victim host. Requires `hping3`, `nmap`, `dig`, and `curl`.

```bash
# Run from the Kali attacker machine
sudo bash scripts/demo_attack.sh <victim-ip>
# Example:
sudo bash scripts/demo_attack.sh 192.168.56.103
```

| Stage | Attack | Spoofed Source | MITRE |
|---|---|---|---|
| 1 | ICMP Sweep | Tor exit node (Germany) | T1018 |
| 2 | Port Scan | Real Kali IP (nmap) | T1046 |
| 3 | SYN Burst | Linode VPS (US) | T1498 |
| 4 | Lateral Movement | Rostelecom (Russia) | T1021 |
| 5 | DNS Tunneling | Real Kali IP | T1071.004 |
| 6 | Web Exploit | Real Kali IP (curl) | T1190 |
| 7 | Slow Loris | CLARO S.A. (Brazil) | T1499 |

---

## Project Structure

```
NETIDS/
├── src/
│   ├── ids.py                          # Entry point — arg parsing, packet routing, dedup, logging
│   ├── rules/
│   │   ├── port_scan.py                # TCP port scan detector
│   │   ├── syn_burst.py                # SYN burst / SYN flood detector
│   │   ├── icmp_sweep.py               # ICMP host discovery detector
│   │   ├── lateral_movement.py         # SSH lateral movement detector
│   │   ├── dns_tunnel.py               # DNS tunneling detector
│   │   ├── web_exploit.py              # SQL injection / path traversal / cmd injection detector
│   │   └── slow_loris.py               # Slow Loris detector
│   ├── enrichment/
│   │   ├── enrich_ip.py                # Reverse DNS, private-IP, country, ASN lookup
│   │   └── mitre_mapper.py             # Maps alert types to MITRE ATT&CK technique IDs
│   ├── correlation/
│   │   └── incident_manager.py         # 120s incident grouping, risk scoring, attack chain detection
│   ├── response/
│   │   ├── notifier.py                 # Console output, webhook notifications, auto-block
│   │   └── ai_triage.py                # Claude Haiku async triage — attack classification + response
│   ├── models/
│   │   ├── alerts.py                   # Alert dataclass definition
│   │   └── incidents.py                # Incident dataclass definition
│   ├── utils/
│   │   └── severity.py                 # Shared severity classification helpers
│   └── dashboard/
│       ├── flask_app.py                # Flask web dashboard (port 5000, login-protected)
│       └── templates/
│           ├── index.html              # Main SOC dashboard
│           └── login.html              # Login page
├── scripts/
│   ├── demo_seed.py                    # Seeds dashboard with 23 realistic multi-country alerts
│   └── demo_attack.sh                  # 7-stage live attack sequence (run from Kali)
├── data/
│   └── training_features.csv           # Feature data for the Isolation Forest model
├── models/
│   └── isolation_forest.pkl            # Trained Isolation Forest anomaly detection model
├── logs/
│   ├── alerts.jsonl                    # Alert log output (auto-generated)
│   └── triage.jsonl                    # AI triage results cache (auto-generated)
├── config.json                         # Thresholds, window sizes, whitelist, log path
├── requirements.txt                    # Python dependencies
├── run_ids.sh                          # Quick-start: runs live capture on enp0s3
├── run_dashboard.sh                    # Quick-start: launches Flask dashboard on port 5000
└── README.md
```

---

## Dependencies

```
scapy==2.7.0
Flask==3.0.3
anthropic
scikit-learn==1.3.2
numpy==1.24.4
pandas==2.0.3
requests==2.32.4
joblib==1.4.2
scipy==1.10.1
rich==13.9.4
plotly==6.5.2
pytz==2025.2
python-dateutil==2.9.0.post0
GitPython==3.1.46
```

```bash
pip install -r requirements.txt
pip install anthropic
```

> Live packet capture (`--live`) requires root/administrator privileges.

---

*NetIDS — Built as a capstone project · [GitHub](https://github.com/LuisVazquez6/NETIDS)*
