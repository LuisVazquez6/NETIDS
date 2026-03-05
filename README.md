# NetIds - Lightweight Network Intrusion Detection System
A lightweight network intrusion detection system (IDS) built in Python that monitors live network traffic or PCAP files, detects suspicious activity using rule-based detectors, and correlates alerts into incidents with risk scoring and MITRE ATTCK mapping.

The system supports realt-time packet capture using Scapy, alert logging, incident correlation
                                                                                                                    

# Features
* Live Network packet capture
* PCAP file analysis
* Multiple attack detectors
* Incident correlation and risk scoring
* MITRE ATTCK technique mapping
* Alert deduplication and cooldowns
* JSONL logging for downstreamn analysis
* Modular rule engine

# Detection Capabilities

Detector                                Description                             MITRE ATTCK
----------------------------------------------------------------------------------------------
Port Scan       |     Detects scanning across multiple ports within a time window   |   T1046 
----------------|-------------------------------------------------------------------|---------
SYN Burst       |     Detects large bursts of TCMP SYN packets indicating potential |   T1498
                |     DoS                                                           |
----------------|-------------------------------------------------------------------|---------
ICMP Flood      |     Detects abnormal ICMP echo traffic volume                     |   T1498
----------------|-------------------------------------------------------------------|---------
SSH Brute Force |     Detects repeated connection attempts to SSH                   |   T1110
----------------------------------------------------------------------------------------------

 # Architecture

                Network Traffic
                       |
                       v
                Packet Capture
                  (Scapy)
                       |
                       v
                Detection Rules
        ┌───────────┬───────────┬───────────┐
        | Port Scan  | SYN Burst | ICMP Flood|
        | SSH Brute  |           |           |
        └───────────┴───────────┴───────────┘
                       |
                       v
                Alert Generation
                       |
                       v
               MITRE Mapping
                       |
                       v
               Incident Correlation
                       |
                       v
               Notification Engine
                       |
                       v
                  JSONL Logs

# Project Structure

netids/
│
├── src/
│   ├── rules/              # Detection rules
│   ├── enrichment/         # MITRE and IP enrichment
│   ├── correlation/        # Incident correlation engine
│   ├── response/           # Notification handler place holder for future implementation 
│   ├── dashboard/          # Streamlit SOC dashboard
│   └── ids.py              # Main IDS engine
│
├── logs/
│   └── alerts.jsonl        # Alert output
│
├── config.json             # Runtime configuration
├── run_ids.sh              # Launch script
├── requirements.txt
└── README.md


# FUTURE IMPROVEMENTS
- Machine learning anomaly detection
- Threat intelligence integration
- Alert dashbaord improvemnts
- Packet payload analysis
- Addition protocol detectos
- Slack/Email Notifications