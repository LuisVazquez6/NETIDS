# NetIDS — Network Intrusion Detection System

> A Python/Scapy IDS that detects real-time attack traffic using rolling time-window thresholds, with a Flask web dashboard, GeoIP enrichment, and MITRE ATT&CK mapping.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.7-green?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=flat-square&logo=flask)
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
- [Alert Format](#alert-format)
- [Detection Thresholds](#detection-thresholds)
- [Demo Attack Script](#demo-attack-script)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)

---

## Overview

NetIDS is a lightweight Network Intrusion Detection System built with Python and Scapy. It supports two operation modes:

- **Live Mode** — Sniffs packets directly from a network interface in real time via Scapy's `sniff()` loop
- **PCAP Mode** — Analyzes pre-captured `.pcap`/`.pcapng` files for offline forensic investigation via `PcapReader`

Detection is based on rolling time-window counters with configurable low/medium/high severity thresholds. All alerts are emitted in **JSON Lines** format for easy parsing and integration with downstream tools. A Flask web dashboard provides real-time visibility with a live alert feed, incident summary, and attack map.

---

## Features

| Feature | Description |
|---|---|
| **TCP Port Scan Detection** | Tracks unique destination ports per source IP in a rolling window |
| **SSH Brute Force Detection** | Flags abnormal SYN rates against port 22 |
| **SYN Burst / SYN Flood Detection** | Detects DoS-indicative SYN packet bursts from a single source |
| **ICMP Flood Detection** | Identifies high-rate ICMP echo request floods |
| **DNS Tunneling Detection** | Flags high-rate or oversized DNS queries indicative of data exfiltration |
| **HTTP Brute Force Detection** | Detects rapid POST request floods against HTTP login endpoints |
| **Slow Loris Detection** | Identifies large numbers of half-open TCP connections targeting a web server |
| **3-Level Severity** | Each detector emits LOW / MEDIUM / HIGH alerts based on configurable thresholds |
| **IP Enrichment** | Reverse DNS, private-IP detection, country, and ASN lookups per alert |
| **MITRE ATT&CK Mapping** | Every alert type is mapped to a MITRE technique ID |
| **Incident Correlation** | Alerts from the same source IP are grouped into incidents with a risk score |
| **IP Whitelist** | Suppress alerts from trusted internal addresses via `config.json` |
| **Auto-Block** | Optional `--auto-block` flag drops HIGH-severity sources via `iptables` (requires root) |
| **JSON Lines Alert Logging** | Structured, timestamped alerts ready for any SIEM pipeline |
| **Flask Dashboard** | Password-protected web UI with live alert feed and incident view on port 5000 |

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
              │  port_scan · ssh_bruteforce      │
              │  syn_burst · icmp_flood          │
              │  dns_tunnel · http_bruteforce    │
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
            Flask dashboard (flask_app.py · port 5000)
```

### Layer breakdown

| Layer | Files | Responsibility |
|---|---|---|
| **Input** | `src/ids.py` | Starts Scapy sniff loop or reads PCAP; routes raw packets to detectors |
| **Detection** | `src/rules/` | Per-packet evaluation against rolling time-window thresholds; 3 severity levels |
| **Enrichment** | `src/enrichment/enrich_ip.py`, `src/enrichment/mitre_mapper.py` | Adds reverse DNS, country/ASN data; maps alert types to MITRE ATT&CK technique IDs |
| **Correlation** | `src/correlation/incident_manager.py` | Groups alerts by `src_ip` in a 120s window; computes a 0–100 risk score |
| **Response** | `src/response/notifier.py` | Colored console output; optional webhook notifications |
| **Dashboard** | `src/dashboard/flask_app.py` | Password-protected Flask UI; reads `logs/alerts.jsonl` in real time |

---

## Installation

```bash
git clone https://github.com/LuisVazquez6/NETIDS.git
cd NETIDS

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirments.txt
```

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

Per-detector overrides (config.json values take priority):
--window N              Port-scan window in seconds (default: 15)
--threshold N           Port-scan port threshold (default: 20)
--icmp-window N         ICMP flood window (default: 10)
--icmp-threshold N      ICMP flood packet threshold (default: 5)
--syn-window N          SYN burst window (default: 5)
--syn-threshold N       SYN burst packet threshold (default: 20)
--ssh-window N          SSH brute-force window (default: 30)
--ssh-threshold N       SSH brute-force attempt threshold (default: 12)
```

---

## Dashboard

The Flask dashboard provides a password-protected web interface at `http://<host>:5000`.

```bash
# Using the helper script
bash run_dashboard.sh

# Or directly
.venv/bin/python3 src/dashboard/flask_app.py
```

The dashboard reads `logs/alerts.jsonl` in real time and displays:
- Live alert feed with severity, source IP, MITRE technique, and enrichment data
- Incident summary grouped by source IP with risk scores
- Protocol and alert-type statistics

A default password is generated on first launch and stored alongside the session key in `.flask_secret` and `.flask_salt` in the project root.

---

## Alert Format

Alerts are written to `logs/alerts.jsonl` — one JSON object per line:

```json
{"alert_type": "PORT_SCAN_SUSPECTED", "severity": "MEDIUM", "src_ip": "192.168.1.105", "dst_ip": "10.0.0.1", "dst_port": 443, "proto": "TCP", "ts": 1748000000.0, "event_id": "a3f9c12b4d7e", "mitre_technique": "T1046", "enrichment": {"src_is_private": true, "src_reverse_dns": "", "dst_service": "https"}, "details": {"unique_ports": 38, "window_s": 15}}
{"alert_type": "SSH_BRUTEFORCE_SUSPECTED", "severity": "HIGH", "src_ip": "203.0.113.44", "dst_port": 22, "proto": "TCP", "ts": 1748000044.0, "event_id": "b7d2e98f1a0c", "mitre_technique": "T1110", "enrichment": {"src_country": "Russia", "src_org": "Rostelecom"}, "details": {"attempt_count": 55, "window_s": 30}}
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
| `enrichment` | Object: reverse DNS, private flag, country, org/ASN, dst service |
| `details` | Object: detector-specific counters (e.g. `unique_ports`, `syn_count`) |

---

## MITRE ATT&CK Mapping

| Alert Type | Technique |
|---|---|
| `PORT_SCAN_SUSPECTED` | T1046 — Network Service Discovery |
| `SYN_BURST_SUSPECTED` | T1498 — Network Denial of Service |
| `ICMP_FLOOD_SUSPECTED` | T1498 — Network Denial of Service |
| `SSH_BRUTEFORCE_SUSPECTED` | T1110 — Brute Force |
| `DNS_TUNNEL_SUSPECTED` | T1071.004 — Application Layer Protocol: DNS |
| `HTTP_BRUTEFORCE_SUSPECTED` | T1110 — Brute Force |
| `SLOW_LORIS_SUSPECTED` | T1499 — Endpoint Denial of Service |

---

## Detection Thresholds

All thresholds are configurable in `config.json`. Each detector has three severity levels:

| Detector | Window | LOW | MEDIUM | HIGH | Trigger condition |
|---|---|---|---|---|---|
| TCP Port Scan | 15s | 15 ports | 30 ports | 60 ports | Unique dst ports from one src |
| ICMP Flood | 10s | 10 pkts | 15 pkts | 50 pkts | ICMP echo requests from one src |
| SYN Burst | 8s | 8 pkts | 12 pkts | 50 pkts | SYN-only packets from one src |
| SSH Brute Force | 30s | 8 hits | 20 hits | 50 hits | SYN packets to port 22 from one src |
| DNS Tunneling | 10s | 20 queries | 40 queries | 80 queries | DNS queries from one src (or oversized labels) |
| HTTP Brute Force | 20s | 10 reqs | 25 reqs | 60 reqs | POST requests from one src |
| Slow Loris | — | 10 conns | 20 conns | 40 conns | Half-open TCP connections from one src |

To override, edit `config.json` at the project root.

---

## Demo Attack Script

`demo_attack.sh` runs a full 8-stage simulated attack sequence from a Kali machine against the IDS victim host. It requires `hping3`, `nmap`, `dig`, and `curl`.

```bash
# Run from the Kali attacker machine
sudo bash demo_attack.sh <victim-ip>
# Example:
sudo bash demo_attack.sh 192.168.56.103
```

Stages:
1. **ICMP Flood** — spoofed Tor exit node source (T1498)
2. **Port Scan** — nmap SYN scan across 50 ports (T1046)
3. **SYN Burst** — 60 SYN packets from spoofed Linode VPS (T1498)
4. **SSH Brute Force** — 35 SYN packets to port 22, spoofed Russian VPS (T1110)
5. **DNS Tunneling** — 50 rapid queries + oversized subdomain label (T1071.004)
6. **HTTP Brute Force** — 30 POST requests to port 8080 login endpoint (T1110)
7. **Slow Loris** — 25 half-open TCP connections from spoofed IP (T1499)

---

## Project Structure

```
NETIDS/
├── src/
│   ├── ids.py                      # Entry point — arg parsing, packet routing, dedup, logging
│   ├── rules/
│   │   ├── port_scan.py            # TCP port scan detector
│   │   ├── ssh_bruteforce.py       # SSH brute force detector
│   │   ├── syn_burst.py            # SYN burst / SYN flood detector
│   │   ├── icmp_flood.py           # ICMP flood detector
│   │   ├── dns_tunnel.py           # DNS tunneling detector
│   │   ├── http_bruteforce.py      # HTTP brute force detector
│   │   └── slow_loris.py           # Slow Loris detector
│   ├── enrichment/
│   │   ├── enrich_ip.py            # Reverse DNS, private-IP, country, ASN lookup
│   │   └── mitre_mapper.py         # Maps alert types to MITRE ATT&CK technique IDs
│   ├── correlation/
│   │   └── incident_manager.py     # 120s incident grouping + 0–100 risk scoring
│   ├── response/
│   │   └── notifier.py             # Console output + optional webhook notifications
│   ├── models/
│   │   ├── alerts.py               # Alert dataclass definition
│   │   └── incidents.py            # Incident dataclass definition
│   ├── utils/
│   │   └── severity.py             # Shared severity helpers
│   └── dashboard/
│       ├── flask_app.py            # Flask web dashboard (port 5000, login-protected)
│       └── templates/
│           ├── index.html          # Main dashboard view
│           └── login.html          # Login page
├── data/
│   └── training_features.csv       # Feature data for the Isolation Forest model
├── models/
│   └── isolation_forest.pkl        # Trained Isolation Forest anomaly detection model
├── logs/
│   └── alerts.jsonl                # Alert log output (auto-generated)
├── graphics/                       # Presentation graphics and generator scripts
├── config.json                     # Thresholds, window sizes, whitelist, log path
├── requirments.txt                 # Python dependencies
├── run_ids.sh                      # Quick-start: runs live capture on enp0s3
├── run_dashboard.sh                # Quick-start: launches Flask dashboard on port 5000
├── demo_attack.sh                  # 8-stage simulated attack sequence (run from Kali)
└── README.md
```

---

## Dependencies

```
scapy==2.7.0
Flask==3.0.3
plotly==6.5.2
scikit-learn==1.3.2
numpy==1.24.4
pandas==2.0.3
requests==2.32.4
rich==13.9.4
joblib==1.4.2
scipy==1.10.1
pytz==2025.2
python-dateutil==2.9.0.post0
GitPython==3.1.46
```

Install all dependencies with:

```bash
pip install -r requirments.txt
```

> **Note:** Live packet capture (`--live`) requires root/administrator privileges.

---

*NetIDS — Built as a capstone project · [GitHub](https://github.com/LuisVazquez6/NETIDS)*
