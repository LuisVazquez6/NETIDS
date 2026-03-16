# NetIDS — Network Intrusion Detection System

A real-time network intrusion detection system built in Python. NetIDS captures live traffic or replays PCAP files, detects attacks using sliding-window rule-based detectors, correlates alerts into incidents with risk scoring, maps techniques to MITRE ATT&CK, and generates SOC narratives using a local LLM (Ollama/Llama 3.2).

---

## Features

- **Live packet capture** via Scapy or offline PCAP replay
- **4 rule-based detectors** with configurable sliding windows and thresholds
- **3-tier severity escalation** — LOW → MEDIUM → HIGH per detector
- **ML anomaly detection** via Isolation Forest
- **Incident correlation** — groups alerts by source IP into incidents with risk scoring (0–100)
- **MITRE ATT&CK mapping** for every alert type
- **IP enrichment** — reverse DNS, service identification, private/public classification
- **Local LLM integration** — SOC-style narrative via Ollama (Llama 3.2, no cloud dependency)
- **Alert deduplication** — cooldown per (alert_type, src_ip, severity) to suppress noise
- **JSONL logging** — append-only, SIEM-ready structured output
- **Streamlit dashboard** — live SOC monitoring UI
- **Webhook support** — Discord/Slack notifications

---

## Detection Capabilities

| Detector | What It Detects | Window | Thresholds (L/M/H) | MITRE |
|----------|----------------|--------|---------------------|-------|
| Port Scan | Unique destination ports from one source | 15s | 10 / 20 / 40 ports | T1046 |
| SYN Burst | High-volume SYN packets (any port) | 8s | 5 / 10 / 13 SYNs | T1498 |
| ICMP Flood | ICMP echo-request volume | 10s | 2 / 5 / 15 packets | T1498 |
| SSH Brute Force | SYN-only packets to port 22 | 30s | 5 / 12 / 30 SYNs | T1110 |

Each detector uses a **deque-based sliding window** — timestamps outside the window are evicted on every packet, keeping memory and CPU usage constant regardless of traffic volume.

---

## Architecture

```
Raw Packets (NIC / PCAP)
         │
         ▼
   ┌─────────────┐
   │   ids.py    │  ← main orchestrator, Scapy sniff loop
   └──────┬──────┘
          │ per packet
   ┌──────▼──────────────────────────────┐
   │         Detection Layer             │
   │  port_scan │ ssh_bruteforce         │
   │  syn_burst │ icmp_flood             │
   └──────┬──────────────────────────────┘
          │ Alert objects
   ┌──────▼──────────────────────────────┐
   │       Enrichment Layer              │
   │  enrich_ip.py + mitre_mapper.py     │
   └──────┬──────────────────────────────┘
          │ enriched Alerts
   ┌──────▼──────────────────────────────┐
   │     Deduplication / Cooldown        │
   │   60s per (alert_type, src, sev)    │
   └──────┬──────────────────────────────┘
          │ deduplicated Alerts
   ┌──────▼──────────────────────────────┐
   │     Incident Correlation            │
   │  incident_manager.py                │
   │  groups by src_ip, 120s window      │
   │  risk score 0–100, expires 300s     │
   └──────┬──────────────────────────────┘
          │
   ┌──────▼──────────────────────────────┐
   │         Output Layer                │
   │  console (colored)                  │
   │  logs/alerts.jsonl                  │
   │  dashboard/app.py (Streamlit)       │
   │  webhooks (Discord/Slack)           │
   └──────┬──────────────────────────────┘
          │ background thread
   ┌──────▼──────────────────────────────┐
   │     AI SOC Analysis (async)         │
   │  llama_analyzer.py → Ollama         │
   │  Llama 3.2 local inference          │
   └─────────────────────────────────────┘
```

---

## Project Structure

```
NETIDS-1/
├── src/
│   ├── ids.py                  # Main engine — packet capture, orchestration
│   ├── rules/
│   │   ├── port_scan.py        # Port scan detector
│   │   ├── syn_burst.py        # SYN burst / DoS detector
│   │   ├── icmp_flood.py       # ICMP flood detector
│   │   └── ssh_bruteforce.py   # SSH brute force detector
│   ├── enrichment/
│   │   ├── enrich_ip.py        # Reverse DNS, service, private/public
│   │   └── mitre_mapper.py     # Alert type → MITRE ATT&CK technique
│   ├── correlation/
│   │   └── incident_manager.py # Groups alerts into incidents, risk scoring
│   ├── ai/
│   │   ├── llama_analyzer.py   # Ollama/Llama 3.2 SOC narrative generator
│   │   ├── feature_extractor.py # Per-source rolling feature vectors
│   │   └── risk_engine.py      # Isolation Forest anomaly detection
│   ├── models/
│   │   └── incidents.py        # Alert and Incident dataclasses
│   ├── response/
│   │   └── notifier.py         # Console + webhook notifications
│   └── dashboard/
│       └── app.py              # Streamlit SOC dashboard
├── models/
│   └── isolation_forest.pkl    # Pre-trained anomaly detection model
├── logs/
│   └── alerts.jsonl            # SIEM-ready alert log (append-only JSONL)
├── demo/
│   └── demo_attack.sh          # Scripted attack sequence for demonstrations
├── config.json                 # Runtime configuration (thresholds, paths)
├── requirements.txt
└── README.md
```

---

## Requirements

- Python 3.8+
- [Ollama](https://ollama.com) with `llama3.2:3b` pulled
- `libpcap` / `npcap` for live capture
- Root/sudo for live packet capture

Install Python dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Pull the LLM model:
```bash
ollama pull llama3.2:3b
```

---

## Running NetIDS

### Live capture
```bash
sudo -E .venv/bin/python src/ids.py --live --iface enp0s3
```

### PCAP replay
```bash
.venv/bin/python src/ids.py --pcap capture.pcap
```

### Streamlit dashboard (separate terminal)
```bash
.venv/bin/streamlit run src/dashboard/app.py
```

### Full setup (3 terminals)

| Terminal | Command |
|----------|---------|
| 1 | `ollama serve` |
| 2 | `sudo -E .venv/bin/python src/ids.py --live --iface enp0s3` |
| 3 | `.venv/bin/streamlit run src/dashboard/app.py` |

---

## Demo

A scripted attack sequence is included for demonstrations. Run from an attacker machine (Kali):

```bash
sudo bash demo_attack.sh <victim-ip>
```

The script triggers all 4 detectors in sequence:
1. ICMP flood → `ICMP_FLOOD_SUSPECTED` MEDIUM → HIGH
2. Port scan → `PORT_SCAN_SUSPECTED` MEDIUM → HIGH
3. SYN burst → `SYN_BURST_SUSPECTED` MEDIUM → HIGH
4. SSH brute force → `SSH_BRUTEFORCE_SUSPECTED` MEDIUM → HIGH

All attacks originate from the same IP, so the incident manager groups them into a single escalating incident.

---

## Configuration

All thresholds and windows are configurable in `config.json`:

```json
{
  "port_scan":     { "window_s": 15, "thresholds": { "low": 10, "medium": 20, "high": 40 } },
  "syn_burst":     { "window_s": 8,  "thresholds": { "low": 5,  "medium": 10, "high": 13 } },
  "icmp_flood":    { "window_s": 10, "thresholds": { "low": 2,  "medium": 5,  "high": 15 } },
  "ssh_bruteforce":{ "window_s": 30, "thresholds": { "low": 5,  "medium": 12, "high": 30 } },
  "ai_detection":  { "enabled": true, "model_path": "models/isolation_forest.pkl", "threshold": -0.05 }
}
```

---

## Alert Output Format

Each alert prints to the console and is appended to `logs/alerts.jsonl`:

```json
{
  "ts": 1773446512.66,
  "alert_type": "SSH_BRUTEFORCE_SUSPECTED",
  "severity": "HIGH",
  "src_ip": "192.168.56.102",
  "dst_ip": "192.168.56.103",
  "dst_port": 22,
  "proto": "TCP",
  "event_id": "37629d33fc24",
  "mitre_technique": "T1110",
  "details": { "window_s": 30, "attempts": 30, "thresholds": { "low": 5, "medium": 12, "high": 30 } },
  "enrichment": { "src_is_private": true, "dst_service": "ssh", "src_reverse_dns": "" },
  "ai_summary": "192.168.56.102 is brute-forcing SSH on 192.168.56.103",
  "ai_explanation": "30 SSH login attempts within 30 seconds, consistent with automated credential stuffing.",
  "ai_recommendation": "Block 192.168.56.102 at the firewall and review /var/log/auth.log for failed logins."
}
```

---

## Technologies

| Component | Technology |
|-----------|-----------|
| Packet capture | Scapy |
| ML anomaly detection | scikit-learn (Isolation Forest) |
| LLM integration | Ollama — Llama 3.2 3B (local, no cloud) |
| Dashboard | Streamlit |
| Logging | JSONL (SIEM-compatible) |
| Language | Python 3.8 |
