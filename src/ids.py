#!/usr/bin/env python3
from __future__ import annotations
from typing import Any, Dict, Optional, List
import os
import argparse
import json
import sys
import time
import traceback
import hashlib
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP, ICMP, sniff, conf  # type: ignore
from rules.port_scan import PortScanDetector
from rules.icmp_flood import ICMPFloodDetector
from rules.syn_burst import SYNBurstDetector
from rules.ssh_bruteforce import SSHBruteForceDetector
from enrichment.enrich_ip import enrich_alert_dict
from correlation.incident_manager import IncidentManager
from response.notifier import Notifier
from models.alerts import Alert

import os
import argparse
import json
import sys
import time
import traceback
import hashlib


# -----------------------
# Alert cooldown / dedupe
# -----------------------
ALERT_COOLDOWN_S = 10
_last_alert_ts = defaultdict(float)

def fingerprint(a: Alert) -> str:
    base = f"{a.alert_type}|{a.src_ip}|{getattr(a, 'dst_ip', None)}|{getattr(a, 'dst_port', None)}|{getattr(a, 'proto', None)}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]

def should_emit(a: Alert) -> bool:
    key = (
        a.alert_type,
        a.src_ip,
        getattr(a, "dst_ip", None),
        getattr(a, "dst_port", None),
        getattr(a, "proto", None),
    )
    now = float(a.ts)
    if now - _last_alert_ts[key] < ALERT_COOLDOWN_S:
        return False
    _last_alert_ts[key] = now
    return True


# -----------------------
# Logger
# -----------------------
class JSONLLogger:
    def __init__(self, out_path: Path):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self.out_path = out_path

    def write(self, alert: Alert) -> None:
        self.write_dict(asdict(alert))

    def write_dict(self, obj: Dict[str, Any]) -> None:
        with self.out_path.open("a", encoding = "utf-8") as f:
            f.write(json.dumps(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())


# -----------------------
# Helpers (thresholds)
# -----------------------
def _int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def pick_thresholds(cfg_thresholds: dict, default_medium: int) -> Dict[str, int]:
    """
    Ensure we have integer thresholds for low/medium/high.
    """
    medium = _int(cfg_thresholds.get("medium"), default_medium)
    low = _int(cfg_thresholds.get("low"), max(1, medium // 2))
    high = _int(cfg_thresholds.get("high"), medium * 3)
    return {"low": low, "medium": medium, "high": high}


# -----------------------
# Packet processing
# -----------------------
def iter_packets(pcap_path: Path):
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            yield pkt


def emit_alerts(alerts: List[Alert], logger: JSONLLogger, incident_mgr: IncidentManager, notifier: Notifier) -> None:
    for a in alerts:
        if hasattr(a, "event_id") and getattr(a, "event_id") is None:
            a.event_id = fingerprint(a)  # type: ignore[attr-defined]

        if not should_emit(a):
            continue

        a_dict = asdict(a)
        a_dict = enrich_alert_dict(a_dict)

        incident, _is_new = incident_mgr.ingest(a_dict)
        inc_dict = incident.to_dict()

        if notifier.should_notify(inc_dict) and inc_dict.get("severity") in ("MEDIUM", "HIGH"):
            notifier.notify_console(inc_dict)

        print(f"[ALERT] {a.alert_type} src={a.src_ip} severity={a.severity} details={a.details}")
        logger.write_dict(a_dict)


def handle_packet(
    pkt,
    stats,
    portscan: PortScanDetector,
    icmp_flood: ICMPFloodDetector,
    syn_burst: SYNBurstDetector,
    ssh_bf: SSHBruteForceDetector,
    logger: JSONLLogger,
    incident_mgr: IncidentManager,
    notifier: Notifier,
) -> None:
    stats["total_packets"] += 1

    if IP not in pkt:
        return
    stats["ip_packets"] += 1

    src = pkt[IP].src
    dst = pkt[IP].dst
    stats["top_src"][src] += 1
    stats["top_dst"][dst] += 1

    ts = float(getattr(pkt, "time", time.time()))

    if TCP in pkt:
        stats["tcp_packets"] += 1
        dport = int(pkt[TCP].dport)
        flags = int(pkt[TCP].flags)

        tcp_alerts: List[Alert] = []
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0

        if is_syn and not is_ack:
            tcp_alerts += portscan.process(ts, src, dst, dport)
            tcp_alerts += ssh_bf.process(ts, src, dst, dport, flags)

        tcp_alerts += syn_burst.process(ts, src, dst, flags)

        ##tcp_alerts += portscan.process(ts, src, dst, dport)
        ##tcp_alerts += syn_burst.process(ts, src, dst, flags)
        ##tcp_alerts += ssh_bf.process(ts, src, dst, dport, flags)

    # enrich for dedupe/fingerprint
        for a in tcp_alerts:
            setattr(a, "dst_ip", dst)
            setattr(a, "dst_port", dport)
            setattr(a, "proto", "TCP")

        emit_alerts(tcp_alerts, logger, incident_mgr, notifier)

    elif UDP in pkt:
        stats["udp_packets"] += 1

    elif ICMP in pkt:
        stats["icmp_packets"] += 1
        if int(pkt[ICMP].type) == 8:
            icmp_alerts = icmp_flood.process(ts, src, dst)
            for a in icmp_alerts:
                setattr(a, "dst_ip", dst)
                setattr(a, "dst_port", None)
                setattr(a, "proto", "ICMP")

            emit_alerts(icmp_alerts, logger, incident_mgr, notifier)


def run_live(
    interface: Optional[str],
    stats,
    portscan: PortScanDetector,
    icmp_flood: ICMPFloodDetector,
    syn_burst: SYNBurstDetector,
    ssh_bf: SSHBruteForceDetector,
    logger: JSONLLogger,
    incident_mgr: IncidentManager,
    notifier: Notifier,
) -> None:
    if interface:
        print(f"[*] Live capture on interface: {interface}")
    else:
        print(f"[*] Live capture on default interface: {conf.iface}")

    def on_packet(pkt):
        try:
            handle_packet(pkt, stats, portscan, icmp_flood, syn_burst, ssh_bf, logger, incident_mgr, notifier)
        except Exception as e:
            print(f"[!] Packet handler error: {e}", file=sys.stderr)
            traceback.print_exc()

    sniff(
        iface=interface,
        prn=on_packet,
        store=False,
        filter="ip",
    )


def summarize(stats) -> None:
    def topn(d, n=5):
        return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]

    print("\n=== SUMMARY ===")
    print(f"Total packets: {stats['total_packets']}")
    print(f"IP packets:    {stats['ip_packets']}")
    print(f"TCP packets:   {stats['tcp_packets']}")
    print(f"UDP packets:   {stats['udp_packets']}")
    print(f"ICMP packets:  {stats['icmp_packets']}")
    print(f"Top src IPs:   {topn(stats['top_src'])}")
    print(f"Top dst IPs:   {topn(stats['top_dst'])}")


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    ap = argparse.ArgumentParser(description="NetIDS MVP: PCAP analyzer + live sniff + rules")
    ap.add_argument("--pcap", default=None, help="Path to .pcap/.pcapng (PCAP mode)")
    ap.add_argument("--live", action="store_true", help="Sniff live packets (live mode)")
    ap.add_argument("--iface", default=None, help="Interface (e.g., enp0s3)")
    ap.add_argument("--log", default="logs/alerts.jsonl", help="Alert output (JSONL)")
    ap.add_argument("--config", default="config.json", help="Path to JSON config")

    # CLI defaults (config can override)
    ap.add_argument("--window", type=int, default=15, help="Port-scan window seconds")
    ap.add_argument("--threshold", type=int, default=20, help="Port-scan distinct port threshold")

    ap.add_argument("--icmp-window", type=int, default=10, help="ICMP sweep window seconds")
    ap.add_argument("--icmp-threshold", type=int, default=5, help="ICMP sweep target threshold")

    ap.add_argument("--syn-window", type=int, default=5, help="SYN burst window seconds")
    ap.add_argument("--syn-threshold", type=int, default=20, help="SYN burst SYN threshold")

    ap.add_argument("--ssh-window", type=int, default=30, help="SSH brute-force window seconds")
    ap.add_argument("--ssh-threshold", type=int, default=12, help="SSH brute-force attempt threshold")

    args = ap.parse_args()
    cfg = load_config(args.config)

    incident_mgr = IncidentManager(window_s=120, max_idle_s=300)
    notifier = Notifier(cooldown_s=20)

    # Logging Path (config overrides CLI)
    ROOT = Path(__file__).resolve().parents[1]  # src/ids.py -> netids/
    log_path = cfg.get("log_path", args.log)

    log_path = Path(log_path)
    if not log_path.is_absolute():
        log_path = ROOT / log_path

    logger = JSONLLogger(log_path)

    # Load rule configs
    ps_cfg = cfg.get("port_scan", {})
    icmp_cfg = cfg.get("icmp_flood", {})
    syn_cfg = cfg.get("syn_burst", {})

    ps_thresholds = pick_thresholds(ps_cfg.get("thresholds", {}), args.threshold)
    icmp_thresholds = pick_thresholds(icmp_cfg.get("thresholds", {}), args.icmp_threshold)
    syn_thresholds = pick_thresholds(syn_cfg.get("thresholds", {}), args.syn_threshold)

    # Create detectors (use MEDIUM as the “active” threshold)
    portscan = PortScanDetector(
        window_s=_int(ps_cfg.get("window_s"), args.window),
        threshold_ports=ps_thresholds["medium"],
    )
    portscan.thresholds = ps_thresholds

    icmp_flood = ICMPFloodDetector(
        window_s = _int(icmp_cfg.get("window_s"), args.icmp_window),
        threshold_pkts = icmp_thresholds["medium"],
    )
    icmp_flood.thresholds = icmp_thresholds

    syn_burst = SYNBurstDetector(
        window_s=_int(syn_cfg.get("window_s"), args.syn_window),
        threshold_syn=syn_thresholds["medium"],
    )
    syn_burst.thresholds = syn_thresholds

    ssh_cfg = cfg.get("ssh_bruteforce", {})
    ssh_thresholds = pick_thresholds(ssh_cfg.get("thresholds", {}), args.ssh_threshold)

    ssh_bf = SSHBruteForceDetector(
        window_s = _int(ssh_cfg.get("window_s"), args.ssh_window),
        threshold_hits = ssh_thresholds["medium"],
    )
    ssh_bf.thresholds = ssh_thresholds
    
    # Professional: print effective config at startup
    print(f"[CFG] log_path={Path(log_path).resolve()}")
    print(f"[CFG] port_scan window_s={portscan.window_s} thresholds={portscan.thresholds}")
    print(f"[CFG] icmp_flood window_s = {icmp_flood.window_s} thresholds = {icmp_flood.thresholds}")
    print(f"[CFG] syn_burst window_s={syn_burst.window_s} thresholds={syn_burst.thresholds}")
    print(f"[CFG] ssh_bruteforce window_s={ssh_bf.window_s} thresholds={ssh_bf.thresholds}")

    stats = {
        "total_packets": 0,
        "ip_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "top_src": defaultdict(int),
        "top_dst": defaultdict(int),
    }

    try:
        if args.live:
            run_live(args.iface, stats, portscan, icmp_flood, syn_burst, ssh_bf, logger, incident_mgr, notifier)
        else:
            if not args.pcap:
                print("[!] Choose one: --live OR --pcap <file>")
                return 2
            pcap_path = Path(args.pcap)
            if not pcap_path.exists():
                print(f"[!] PCAP not found: {pcap_path}")
                return 2

            print(f"[*] Reading PCAP: {pcap_path}")
            for pkt in iter_packets(pcap_path):
                handle_packet(pkt, stats, portscan, icmp_flood, syn_burst, ssh_bf, logger, incident_mgr, notifier)

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        summarize(stats)
        print(f"Alerts saved to: {Path(log_path).resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())