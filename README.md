# NetIDS — Network Intrusion Detection System

> A Python-based IDS that detects reconnaissance and attack behavior in real time using rolling time windows and threshold-based logic.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Scapy](https://img.shields.io/badge/Scapy-2.7%2B-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Installation](#installation)
- [Usage](#usage)
- [Alert Format](#alert-format)
- [Detection Thresholds](#detection-thresholds)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)

---

## Overview

NetIDS is a lightweight Network Intrusion Detection System built with Python and Scapy. It supports two operation modes:

- **Live Mode** — Sniffs packets directly from a network interface in real time via Scapy
- **PCAP Mode** — Analyzes pre-captured `.pcap` / `.pcapng` files for offline investigation

Detection is based on rolling time-window counters and configurable per-detector thresholds with three severity tiers (LOW / MEDIUM / HIGH). Alerts are emitted in **JSON Lines** format for easy integration with any SIEM pipeline. A Flask web dashboard provides a real-time incident view.

---

## Features

| Feature | Description |
|---|---|
| **TCP Port Scan Detection** | Tracks unique destination ports per source IP in a rolling window |
| **SSH Brute Force Detection** | Flags high SYN-packet rates targeting port 22 |
| **SYN Burst / SYN Flood Detection** | Detects DoS-indicative SYN packet bursts from a single source |
| **ICMP Flood Detection** | Identifies ICMP echo request floods from a single source |
| **DNS Tunneling Detection** | Dual-signal: high query rate OR unusually long query names (>= 75 chars) |
| **HTTP Brute Force Detection** | Counts repeated POST requests from the same source to the same target |
| **Slow Loris Detection** | Tracks half-open TCP connections; triggers on excessive concurrent connections |
| **Live Packet Capture** | Real-time sniffing on any interface via Scapy |
| **PCAP File Analysis** | Offline forensic analysis of captured traffic |
| **MITRE ATT&CK Mapping** | Enriches every alert with the relevant technique ID |
| **IP Enrichment** | Adds geolocation (country, ASN/org) and reverse DNS to each alert |
| **Incident Correlation** | Groups alerts from the same `src_ip` within a 120s window; computes a 0–100 risk score |
| **Attack Chain Detection** | Recognizes multi-stage patterns (e.g., Recon → SSH Exploitation) |
| **Alert Deduplication** | 60-second cooldown per `(alert_type, src_ip, severity)` to prevent alert fatigue |
| **JSON Lines Alert Logging** | Structured, timestamped alerts written to `logs/alerts.jsonl` |
| **Colored Console Output** | Severity-colored terminal output (RED = HIGH, YELLOW = MEDIUM, GREEN = LOW) |
| **Webhook Notifications** | Discord / Slack integration for incident alerts |
| **Auto-Blocking** | Optional `iptables`-based auto-block of HIGH-severity sources (requires root) |
| **Flask Dashboard** | Web UI showing live incidents, timelines, and MITRE mappings |

---

## How It Works

### Rolling time window

Each detector tracks per-source-IP events inside a configurable sliding window. On each packet:

1. Retrieve the source IP's event history
2. Prune events older than the window duration
3. Append the new event
4. If the count exceeds a severity threshold → emit an alert

```
Time ────────────────────────────────────────────────▶
      [ pruned ] | ←──── window (e.g. 15s) ────→ | now
                         ^^^^^^^^^^^^^^^^^^^^
                         Count events here
                         If count > threshold → ALERT
```

### Severity tiers

Every detector has three configurable thresholds. A single attack can escalate from LOW to MEDIUM to HIGH as it intensifies. The severity is included in the deduplication key, so an escalation always produces a new alert.

### Incident correlation & risk scoring

After deduplication, `incident_manager.py` groups alerts from the same `src_ip` within a 120-second window into an **incident**. Each incident receives a 0–100 risk score based on the number and severity of constituent alerts. Incidents expire after 300 seconds of inactivity. The correlation layer also checks for predefined **attack chain patterns** (e.g., port scan followed by SYN flood) and flags them on the incident.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/LuisVazquez6/NETIDS.git
cd NETIDS

# Install dependencies
pip install -r requirments.txt

# Or install manually
pip install scapy flask pandas plotly
```

> **Note:** Live packet capture requires root / administrator privileges.

---

## Usage

Run all commands from the `src/` directory (or set `PYTHONPATH` to `src/`).

### Live capture

```bash
# Capture on a specific interface
sudo python src/ids.py --live --iface eth0

# With a custom log path
sudo python src/ids.py --live --iface eth0 --log /tmp/alerts.jsonl

# Enable auto-blocking of HIGH-severity sources (iptables, requires root)
sudo python src/ids.py --live --iface eth0 --auto-block
```

### PCAP analysis

```bash
python src/ids.py --pcap capture.pcap
python src/ids.py --pcap capture.pcap --log results.jsonl
```

### Flask dashboard

```bash
python src/dashboard/flask_app.py
```

### CLI options

| Flag | Default | Description |
|---|---|---|
| `--live` | — | Enable live packet capture |
| `--pcap FILE` | — | Read from a PCAP / PCAPNG file |
| `--iface IFACE` | system default | Network interface for live mode |
| `--log PATH` | `logs/alerts.jsonl` | Alert output file (JSON Lines) |
| `--config PATH` | `config.json` | Config file with thresholds |
| `--auto-block` | off | Auto-block HIGH sources via iptables |

---

## Alert Format

Alerts are written in **JSON Lines** format — one JSON object per line:

```json
{"ts": 1748000000.0, "alert_type": "PORT_SCAN_SUSPECTED", "severity": "HIGH", "src_ip": "192.168.1.105", "dst_ip": "192.168.1.1", "dst_port": 443, "proto": "TCP", "mitre_technique": "T1046", "enrichment": {"src_country": "US", "src_org": "Example ISP"}, "details": {"window_s": 15, "distinct_ports": 65}}
{"ts": 1748000010.0, "alert_type": "SYN_BURST_DETECTED", "severity": "HIGH", "src_ip": "10.0.0.22", "mitre_technique": "T1499", "details": {"window_s": 8, "syn_count": 55}}
{"ts": 1748000020.0, "alert_type": "SSH_BRUTEFORCE_SUSPECTED", "severity": "MEDIUM", "src_ip": "203.0.113.44", "mitre_technique": "T1110", "details": {"window_s": 30, "attempt_count": 23}}
{"ts": 1748000030.0, "alert_type": "DNS_TUNNEL_SUSPECTED", "severity": "HIGH", "src_ip": "172.16.0.8", "mitre_technique": "T1071.004", "details": {"query_name": "aaaaaa...example.com", "reason": "long_name"}}
```

| Field | Description |
|---|---|
| `ts` | Unix timestamp of the alert |
| `alert_type` | Detection type (e.g. `PORT_SCAN_SUSPECTED`, `SSH_BRUTEFORCE_SUSPECTED`) |
| `severity` | `LOW`, `MEDIUM`, or `HIGH` |
| `src_ip` | Source IP that triggered the alert |
| `mitre_technique` | MITRE ATT&CK technique ID |
| `enrichment` | Geolocation and ASN data (when available) |
| `details` | Detector-specific counts and window size |

---

## Detection Thresholds

Default thresholds from `config.json` (all are configurable):

| Detector | Window | LOW | MEDIUM | HIGH | MITRE |
|---|---|---|---|---|---|
| TCP Port Scan | 15s | 15 ports | 30 ports | 60 ports | T1046 |
| SYN Burst | 8s | 8 packets | 12 packets | 50 packets | T1499 |
| ICMP Flood | 10s | 10 packets | 15 packets | 50 packets | T1018 |
| SSH Brute Force | 30s | 8 attempts | 20 attempts | 50 attempts | T1110 |
| DNS Tunneling | 10s | 20 queries | 40 queries | 80 queries | T1071.004 |
| HTTP Brute Force | 20s | 10 requests | 25 requests | 60 requests | T1110.003 |
| Slow Loris | — | 10 connections | 20 connections | 40 connections | T1499 |

---

## Project Structure

```
NETIDS/
├── src/
│   ├── ids.py                      # Entry point — arg parsing, packet capture orchestrator
│   ├── rules/
│   │   ├── port_scan.py            # TCP port scan detector
│   │   ├── ssh_bruteforce.py       # SSH brute force detector
│   │   ├── syn_burst.py            # SYN burst / SYN flood detector
│   │   ├── icmp_flood.py           # ICMP flood detector
│   │   ├── dns_tunnel.py           # DNS tunneling detector
│   │   ├── http_bruteforce.py      # HTTP brute force detector
│   │   └── slow_loris.py           # Slow Loris detector
│   ├── enrichment/
│   │   ├── enrich_ip.py            # IP geolocation + ASN lookup
│   │   └── mitre_mapper.py         # Maps alert types to MITRE ATT&CK IDs
│   ├── correlation/
│   │   └── incident_manager.py     # 120s incident grouping + 0–100 risk scoring
│   ├── response/
│   │   └── notifier.py             # Console output, webhook notifications, auto-blocking
│   ├── models/
│   │   ├── alerts.py               # Alert dataclass
│   │   └── incidents.py            # Incident dataclass
│   ├── utils/
│   │   └── severity.py             # Severity classification helpers
│   └── dashboard/
│       ├── flask_app.py            # Flask web dashboard
│       └── templates/
│           ├── index.html          # Main dashboard view
│           └── login.html          # Login page
├── config.json                     # Per-detector thresholds and window sizes
├── requirments.txt                 # Python dependencies
├── demo_attack.sh                  # Demo script that simulates all 7 attack types
├── logs/
│   └── alerts.jsonl                # Alert log (auto-generated)
└── README.md
```

---

## Dependencies

- [Python 3.8+](https://www.python.org/)
- [Scapy 2.7+](https://scapy.net/) — Packet capture and parsing
- [Flask](https://flask.palletsprojects.com/) — Web dashboard
- [Pandas](https://pandas.pydata.org/) — Alert data processing
- [Plotly](https://plotly.com/python/) — Dashboard charts

---

*NetIDS — Built as a capstone project · [GitHub](https://github.com/LuisVazquez6/NETIDS)*
