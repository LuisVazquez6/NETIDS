# NetIDS — Network Intrusion Detection System

> A Python/Scapy IDS that detects real-time attack traffic using rolling time-window thresholds, with a Flask web dashboard, live attack map, GeoIP enrichment, and MITRE ATT&CK mapping.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.7-green?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-3.0-lightgrey?style=flat-square&logo=flask)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Detection Rules](#detection-rules)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Dashboard](#dashboard)
- [Alert Format](#alert-format)
- [Detection Thresholds](#detection-thresholds)
- [Demo Attack Script](#demo-attack-script)
- [Project Structure](#project-structure)

---

## Overview

NetIDS is a lightweight Network Intrusion Detection System built for a university capstone project. It sniffs live traffic from a network interface using Scapy, evaluates every packet against 7 detection rules, enriches alerts with GeoIP data, and streams everything to a Flask web dashboard with a live attack map.

**Deployment model:** Ubuntu victim VM (VirtualBox) + Kali Linux attacker VM, host-only network.

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Network Interface                     │
│              Scapy sniff loop  (ids.py)                  │
└───────────────────────────┬──────────────────────────────┘
                            │ raw packets
                            ▼
┌──────────────────────────────────────────────────────────┐
│                    Detection Layer (src/rules/)          │
│  port_scan · ssh_bruteforce · syn_burst · icmp_flood     │
│  dns_tunnel · http_bruteforce · slow_loris               │
└───────────────────────────┬──────────────────────────────┘
                            │ alert dicts
                            ▼
┌──────────────────────────────────────────────────────────┐
│                   Enrichment Layer                       │
│  enrich_ip.py — GeoIP (ip-api.com), reverse DNS, ASN    │
│  mitre_mapper.py — MITRE ATT&CK technique IDs           │
└───────────────────────────┬──────────────────────────────┘
                            │ enriched alerts
                            ▼
┌──────────────────────────────────────────────────────────┐
│                    Output Layer                          │
│  logs/alerts.jsonl  ·  colored console                   │
└───────────────────────────┬──────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────┐
│              Flask Dashboard (flask_app.py)              │
│  Login · Alert feed · Stats · Live map · Incidents       │
└──────────────────────────────────────────────────────────┘
```

### Layer breakdown

| Layer | Files | Responsibility |
|---|---|---|
| **Capture** | `src/ids.py` | Scapy sniff loop; routes each packet to all rules |
| **Detection** | `src/rules/*.py` | Rolling time-window counters; emit alerts at LOW/MEDIUM/HIGH |
| **Enrichment** | `src/enrichment/enrich_ip.py`, `mitre_mapper.py` | GeoIP (lat/lon/country/org), reverse DNS, MITRE technique |
| **Correlation** | `src/correlation/incident_manager.py` | Groups alerts by source IP; computes 0–100 risk score; detects attack chains |
| **Dashboard** | `src/dashboard/flask_app.py` | REST API + Jinja2 frontend; login with PBKDF2-HMAC auth |

---

## Detection Rules

| Rule | MITRE | What it detects | Alert types |
|---|---|---|---|
| **Port Scan** | T1046 | Too many unique destination ports from one source in a window | `PORT_SCAN_SUSPECTED` |
| **SSH Brute Force** | T1110 | High rate of SYN packets to port 22 from one source | `SSH_BRUTEFORCE_SUSPECTED` |
| **SYN Burst** | T1498 | High rate of TCP SYN packets (any port) from one source | `SYN_BURST_SUSPECTED` |
| **ICMP Flood** | T1498 | High rate of ICMP echo requests from one source | `ICMP_FLOOD_SUSPECTED` |
| **DNS Tunneling** | T1071.004 | High DNS query rate or abnormally long subdomain labels | `DNS_TUNNEL_SUSPECTED` |
| **HTTP Brute Force** | T1110 | High rate of HTTP POST requests from one source | `HTTP_BRUTEFORCE_SUSPECTED` |
| **Slow Loris** | T1499 | Many half-open TCP connections accumulating over time | `SLOW_LORIS_SUSPECTED` |

Each rule uses a **rolling time window** — events older than the window are pruned on every packet, so detection is always based on recent traffic only.

---

## Features

- **7 detection rules** covering reconnaissance, flooding, brute force, and exfiltration
- **Three severity levels** — LOW / MEDIUM / HIGH — with configurable thresholds per rule
- **MITRE ATT&CK mapping** on every alert
- **GeoIP enrichment** via ip-api.com (country, ASN/org, latitude, longitude)
- **Attack chain detection** — identifies multi-stage sequences (e.g. Recon → SYN Flood → Brute Force)
- **Flask dashboard** with login, live alert feed, stats charts, and Leaflet.js attack map
- **IP whitelist** support in `config.json`
- **JSON Lines logging** — one structured alert per line in `logs/alerts.jsonl`
- **Demo attack script** (`demo_attack.sh`) — runs all 7 attacks from Kali with spoofed source IPs

---

## Installation

```bash
git clone https://github.com/LuisVazquez6/NETIDS.git
cd NETIDS

python3 -m venv .venv
source .venv/bin/activate
pip install scapy flask
```

> **Note:** Live packet capture requires root. Use the full venv path with sudo (see Usage).

---

## Usage

### Start the IDS (live capture)

```bash
# Using the helper script (runs as root with the venv Python)
bash run_ids.sh

# Or manually
sudo /home/ids-victim/NETIDS/.venv/bin/python3 src/ids.py --live --iface enp0s3
```

Replace `enp0s3` with your actual network interface (`ip a` to check).

### Start the Flask dashboard

```bash
source .venv/bin/activate
python3 src/dashboard/flask_app.py
```

Then open `http://<vm-ip>:5000` in a browser.

Default credentials: `admin` / `netids2025` (set in `config.json` or via env vars `NETIDS_USER` / `NETIDS_PASSWORD_HASH`).

---

## Dashboard

The web dashboard provides:

- **Alert feed** — live table of all alerts with type, source IP, severity, country, and timestamp
- **Stats panel** — total / HIGH / MEDIUM / LOW counts; alerts by type; top attacker IPs
- **Timeline chart** — alerts per hour over the last 12 hours
- **Live attack map** — Leaflet.js map with pulsing markers for each attacker IP, colored by severity, with popups showing IP / country / org / alert count
- **Incidents panel** — attacker incidents grouped by source IP with risk score (0–100) and detected attack chains

The dashboard auto-refreshes every 10 seconds.

---

## Alert Format

Alerts are written to `logs/alerts.jsonl` — one JSON object per line:

```json
{
  "alert_type": "SSH_BRUTEFORCE_SUSPECTED",
  "severity": "MEDIUM",
  "src_ip": "95.173.136.70",
  "dst_port": 22,
  "ts": 1747176000.123,
  "details": { "count": 23, "window_s": 30 },
  "mitre": { "technique": "T1110", "name": "Brute Force" },
  "enrichment": {
    "src_country": "Russia",
    "src_country_code": "RU",
    "src_org": "AS12389 Rostelecom",
    "src_lat": 55.7522,
    "src_lon": 37.6156,
    "src_is_private": false,
    "src_reverse_dns": "",
    "dst_service": "ssh"
  }
}
```

---

## Detection Thresholds

All thresholds are configurable in `config.json`:

| Rule | Window | LOW | MEDIUM | HIGH |
|---|---|---|---|---|
| Port Scan | 15s | 15 ports | 30 ports | 60 ports |
| SSH Brute Force | 30s | 8 pkts | 20 pkts | 50 pkts |
| SYN Burst | 8s | 8 pkts | 12 pkts | 50 pkts |
| ICMP Flood | 10s | 10 pkts | 15 pkts | 50 pkts |
| DNS Tunnel | 10s | 20 queries | 40 queries | 80 queries |
| HTTP Brute Force | 20s | 10 reqs | 25 reqs | 60 reqs |
| Slow Loris | — | 10 conns | 20 conns | 40 conns |

---

## Demo Attack Script

`demo_attack.sh` runs all 7 attack stages from a Kali Linux machine using `hping3`, `nmap`, `dig`, and `curl`. Source IPs are spoofed to simulate attacks from 5 different countries.

```bash
# On Kali (run as root)
sudo bash demo_attack.sh <victim-ip>
# Example:
sudo bash demo_attack.sh 192.168.56.103
```

| Stage | Tool | Spoofed IP | Country | Expected Alert |
|---|---|---|---|---|
| 1 — ICMP Flood | hping3 | 185.220.101.45 | Germany (Tor) | `ICMP_FLOOD_SUSPECTED` MEDIUM |
| 2 — Port Scan | nmap | (real Kali IP) | — | `PORT_SCAN_SUSPECTED` MEDIUM |
| 3 — SYN Burst | hping3 | 45.33.32.156 | US (Linode) | `SYN_BURST_SUSPECTED` HIGH |
| 4 — SSH Brute Force | hping3 | 95.173.136.70 | Russia | `SSH_BRUTEFORCE_SUSPECTED` MEDIUM |
| 5 — ARP Spoof | — | (skipped) | — | — |
| 6 — DNS Tunnel | dig | (real Kali IP) | — | `DNS_TUNNEL_SUSPECTED` HIGH |
| 7 — HTTP Brute Force | curl | (real Kali IP) | — | `HTTP_BRUTEFORCE_SUSPECTED` MEDIUM |
| 8 — Slow Loris | hping3 | 177.75.32.5 | Brazil | `SLOW_LORIS_SUSPECTED` HIGH |

> ARP spoofing is skipped because it disrupts the VirtualBox network stack.
> A simple HTTP server must be running on the victim (`python3 -m http.server 8080`) for stage 7.

---

## Project Structure

```
NETIDS/
├── config.json                     # All detection thresholds and whitelist
├── run_ids.sh                      # Helper: runs IDS as root with venv Python
├── demo_attack.sh                  # Kali attack demo script
├── requirments.txt                 # Python dependencies
├── logs/
│   └── alerts.jsonl                # Alert output (auto-generated, git-ignored)
├── src/
│   ├── ids.py                      # Entry point — Scapy sniff loop, routes packets
│   ├── rules/
│   │   ├── port_scan.py            # T1046 — unique dst port counter
│   │   ├── ssh_bruteforce.py       # T1110 — SYN rate to port 22
│   │   ├── syn_burst.py            # T1498 — TCP SYN rate (all ports)
│   │   ├── icmp_flood.py           # T1498 — ICMP echo request rate
│   │   ├── dns_tunnel.py           # T1071.004 — DNS query rate + long labels
│   │   ├── http_bruteforce.py      # T1110 — HTTP POST rate
│   │   └── slow_loris.py           # T1499 — half-open TCP connection tracking
│   ├── enrichment/
│   │   ├── enrich_ip.py            # GeoIP (ip-api.com), reverse DNS, lat/lon
│   │   └── mitre_mapper.py         # Alert type → MITRE technique mapping
│   ├── correlation/
│   │   └── incident_manager.py     # Incident grouping, risk scoring, chain detection
│   ├── models/
│   │   ├── alerts.py               # Alert dataclass / schema
│   │   └── incidents.py            # Incident dataclass + SEVERITY_ORDER
│   ├── utils/
│   │   └── severity.py             # Severity helpers
│   ├── response/
│   │   └── notifier.py             # (Optional) webhook notifications
│   └── dashboard/
│       ├── flask_app.py            # Flask app — REST API + session auth
│       └── templates/
│           ├── index.html          # Main dashboard (charts, map, alert feed)
│           └── login.html          # Login page
└── README.md
```

---

## Dependencies

- [Python 3.8+](https://www.python.org/)
- [Scapy 2.7](https://scapy.net/) — Packet capture and parsing
- [Flask 3.0](https://flask.palletsprojects.com/) — Web dashboard
- [ip-api.com](http://ip-api.com/) — Free GeoIP lookups (no API key required)
- [Leaflet.js](https://leafletjs.com/) — Interactive attack map (loaded from CDN)

---

*NetIDS — Capstone Project · [GitHub](https://github.com/LuisVazquez6/NETIDS)*
