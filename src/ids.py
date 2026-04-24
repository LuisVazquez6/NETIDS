#!/usr/bin/env python3
from __future__ import annotations

# -----------------------
# Standard library imports
# -----------------------
# just the built in python stuff we need
import os
import argparse
import json
import sys
import time
import traceback
import hashlib
import threading
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, List

# -----------------------
# Third-party imports
# -----------------------
# scapy does all the packet capture and parsing for us
# handles both live sniffing and reading from pcap files
from scapy.all import PcapReader, IP, TCP, UDP, ICMP, ARP, DNS, Raw, sniff, conf  # type: ignore


# -----------------------
# Internal imports
# -----------------------
# all the modules we built, detectors, enrichment, correlation, AI, output
# keeping each one separate makes it easier to add new detectors later
from rules.port_scan import PortScanDetector
from rules.icmp_flood import ICMPFloodDetector
from rules.syn_burst import SYNBurstDetector
from rules.ssh_bruteforce import SSHBruteForceDetector
from rules.dns_tunnel import DNSTunnelDetector
from rules.http_bruteforce import HTTPBruteForceDetector
from rules.slow_loris import SlowLorisDetector
from enrichment.enrich_ip import enrich_alert_dict
from enrichment.mitre_mapper import map_mitre
from correlation.incident_manager import IncidentManager
from response.notifier import Notifier
from models.alerts import Alert

# -----------------------
# ANSI colors
# -----------------------
# color code by severity so the important stuff jumps out in the terminal
# red = high, yellow = medium, green = low
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
WHITE = "\033[97m"

SEV_COLOR = {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}

# -----------------------
# Alert cooldown / dedupe
# -----------------------
# without this the same alert would fire hundreds of times during an attack
# we wait 60 seconds before firing the same alert type from the same source again
# severity is part of the key so if it escalates from medium to high it still gets through
ALERT_COOLDOWN_S = 60
_last_alert_ts = defaultdict(float)
_last_alert_ts_lock = threading.Lock()


def fingerprint(a: Alert) -> str:
    base = f"{a.alert_type}|{a.src_ip}|{getattr(a, 'dst_ip', None)}|{getattr(a, 'dst_port', None)}|{getattr(a, 'proto', None)}"
    return hashlib.sha1(base.encode("utf-8")).hexdigest()[:12]


def should_emit(a: Alert) -> bool:
    key = (
        a.alert_type,
        a.src_ip,
        getattr(a, "dst_ip", None),
        a.severity,
    )
    now = float(a.ts)
    with _last_alert_ts_lock:
        if now - _last_alert_ts[key] < ALERT_COOLDOWN_S:
            return False
        _last_alert_ts[key] = now
    return True


# -----------------------
# JSONL logger
# -----------------------
# writes every alert to a .jsonl file, one json object per line
# this format works with splunk, elk, grafana, basically any siem
# fsync on every write so we dont lose anything if the process gets killed
class JSONLLogger:
    def __init__(self, out_path: Path):
        out_path.parent.mkdir(parents=True, exist_ok=True)
        self.out_path = out_path

    def write(self, alert: Alert) -> None:
        self.write_dict(asdict(alert))

    def write_dict(self, obj: Dict[str, Any]) -> None:
        with self.out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj) + "\n")
            f.flush()
            os.fsync(f.fileno())


# -----------------------
# Console output
# -----------------------
# prints the full alert block to the terminal with colors and all the details
# the AI fields show "no summary available" at first because the AI runs in a
# background thread and prints its result separately a few seconds later
def format_ts(ts: Any) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def print_alert_console(a_dict: Dict[str, Any]) -> None:
    title = a_dict.get("alert_type", "UNKNOWN_ALERT")
    ts = format_ts(a_dict.get("ts", time.time()))
    src_ip = a_dict.get("src_ip", "N/A")
    dst_ip = a_dict.get("dst_ip", "N/A")
    dst_port = a_dict.get("dst_port", "N/A")
    proto = a_dict.get("proto", "N/A")
    severity = a_dict.get("severity", "N/A")
    mitre = a_dict.get("mitre_technique", "N/A")
    event_id = a_dict.get("event_id", "N/A")

    enrichment = a_dict.get("enrichment", {}) or {}
    dst_service = enrichment.get("dst_service", "")
    src_reverse_dns = enrichment.get("src_reverse_dns", "")
    src_is_private = enrichment.get("src_is_private", "N/A")
    src_country = enrichment.get("src_country", "")
    src_org = enrichment.get("src_org", "")

    c = SEV_COLOR.get(severity, WHITE)

    print("\n" + c + "=" * 72 + RESET)
    print(f"{c}{BOLD} ALERT [{severity}]: {title}{RESET}")
    print(c + "=" * 72 + RESET)
    print(f"{DIM} Time:        {RESET}{ts}")
    print(f"{DIM} Event ID:    {RESET}{event_id}")
    print(f" Severity:    {c}{BOLD}{severity}{RESET}")
    print(f"{DIM} MITRE:       {RESET}{CYAN}{mitre}{RESET}")
    print(f"{DIM} Source:      {RESET}{BOLD}{src_ip}{RESET}")
    print(f"{DIM} Src DNS:     {RESET}{src_reverse_dns or 'N/A'}")
    print(f"{DIM} Src Private: {RESET}{src_is_private}")
    if src_country:
        print(f"{DIM} Src Country: {RESET}{src_country} ({enrichment.get('src_country_code', '')})")
    if src_org:
        print(f"{DIM} Src Org/ASN: {RESET}{src_org}")
    print(f"{DIM} Destination: {RESET}{dst_ip}:{dst_port}")
    print(f"{DIM} Protocol:    {RESET}{proto}")
    print(f"{DIM} Service:     {RESET}{dst_service or 'N/A'}")

    details = a_dict.get("details", {})
    if details:
        print(f"\n{BOLD} Detection Details:{RESET}")
        for k, v in details.items():
            print(f"   {DIM}-{RESET} {k}: {v}")

    print(c + "=" * 72 + RESET)


# -----------------------
# Config helpers
# -----------------------
# reads thresholds and window sizes out of config.json
# if something is missing or broken it falls back to a default instead of crashing
def _int(x: Any, default: int) -> int:
    try:
        return int(x)
    except Exception:
        return default


def pick_thresholds(cfg_thresholds: dict, default_medium: int) -> Dict[str, int]:
    medium = _int(cfg_thresholds.get("medium"), default_medium)
    low = _int(cfg_thresholds.get("low"), max(1, medium // 2))
    high = _int(cfg_thresholds.get("high"), medium * 3)
    return {"low": low, "medium": medium, "high": high}


def load_config(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    with p.open("r", encoding="utf-8") as f:
        return json.load(f)


# -----------------------
# Alert emission
# -----------------------
# every alert that passes the cooldown check goes through this pipeline:
# mitre mapping -> ip enrichment -> incident correlation -> print -> log -> AI
def emit_alerts(alerts: List[Alert], logger: JSONLLogger, incident_mgr: IncidentManager, notifier: Notifier, whitelist: set = None) -> None:
    for a in alerts:
        if whitelist and a.src_ip in whitelist:
            continue

        if hasattr(a, "event_id") and getattr(a, "event_id") is None:
            a.event_id = fingerprint(a)  # type: ignore[attr-defined]

        if not should_emit(a):
            continue

        a_dict = asdict(a)
        a_dict["mitre_technique"] = map_mitre(a.alert_type)
        a_dict = enrich_alert_dict(a_dict)

        incident, is_new, escalated = incident_mgr.ingest(a_dict)
        inc_dict = incident.to_dict()

        if (is_new or escalated) and notifier.should_notify(inc_dict):
            notifier.notify_console(inc_dict)
            notifier.notify_webhook(inc_dict)

        print_alert_console(a_dict)
        logger.write_dict(a_dict)



# -----------------------
# Packet processing
# -----------------------
# every packet comes through here after scapy captures it
# we check the protocol and route it to the right detectors
# pure SYN packets go to port scan and ssh brute force
# all SYNs go to the SYN burst detector regardless of port
# ICMP echo requests go to the flood detector
# UDP is counted but we dont have a detector for it yet
def iter_packets(pcap_path: Path):
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            yield pkt


def handle_packet(pkt, stats, portscan, icmp_flood, syn_burst, ssh_bf, logger, incident_mgr, notifier, dns_tunnel=None, http_bf=None, slow_loris=None, whitelist=None) -> None:
    stats["total_packets"] += 1

    ts = float(getattr(pkt, "time", time.time()))

    if IP not in pkt:
        return
    stats["ip_packets"] += 1

    src = pkt[IP].src
    dst = pkt[IP].dst

    stats["top_src"][src] += 1
    stats["top_dst"][dst] += 1

    if TCP in pkt:
        stats["tcp_packets"] += 1
        dport = int(pkt[TCP].dport)
        sport = int(pkt[TCP].sport)
        flags = int(pkt[TCP].flags)

        tcp_alerts: List[Alert] = []
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0

        # only pure SYN packets go to port scan and ssh detectors
        if is_syn and not is_ack:
            tcp_alerts += portscan.process(ts, src, dst, dport)
            tcp_alerts += ssh_bf.process(ts, src, dst, dport, flags)

        tcp_alerts += syn_burst.process(ts, src, dst, flags)

        # slow loris tracks all TCP packets to follow connection lifecycle
        if slow_loris is not None:
            tcp_alerts += slow_loris.process(ts, src, dst, sport, dport, flags)

        # HTTP brute force — inspect payload of established connections
        if http_bf is not None and Raw in pkt:
            payload = bytes(pkt[Raw].load)
            tcp_alerts += http_bf.process(ts, src, dst, dport, payload)

        for a in tcp_alerts:
            setattr(a, "dst_ip", dst)
            setattr(a, "dst_port", dport)
            setattr(a, "proto", "TCP")

        if tcp_alerts:
            emit_alerts(tcp_alerts, logger, incident_mgr, notifier, whitelist)

    elif UDP in pkt:
        stats["udp_packets"] += 1

        # DNS tunneling detection — port 53 UDP with a DNS query layer
        if dns_tunnel is not None and int(pkt[UDP].dport) == 53 and DNS in pkt:
            dns_layer = pkt[DNS]
            if dns_layer.qd is not None:
                try:
                    qname = dns_layer.qd.qname.decode("utf-8", errors="replace").rstrip(".")
                except Exception:
                    qname = ""
                if qname:
                    dns_alerts = dns_tunnel.process(ts, src, dst, qname)
                    for a in dns_alerts:
                        setattr(a, "dst_ip", dst)
                        setattr(a, "dst_port", 53)
                        setattr(a, "proto", "UDP/DNS")
                    if dns_alerts:
                        emit_alerts(dns_alerts, logger, incident_mgr, notifier, whitelist)

    elif ICMP in pkt:
        stats["icmp_packets"] += 1

        # type 8 is echo request, thats what a flood looks like
        if int(pkt[ICMP].type) == 8:
            icmp_alerts = icmp_flood.process(ts, src, dst)

            for a in icmp_alerts:
                setattr(a, "dst_ip", dst)
                setattr(a, "dst_port", None)
                setattr(a, "proto", "ICMP")

            if icmp_alerts:
                emit_alerts(icmp_alerts, logger, incident_mgr, notifier, whitelist)



# -----------------------
# Capture modes
# -----------------------
# two ways to run: live capture on an interface or replay a pcap file
# live mode just runs until you hit ctrl+c
def run_live(interface, stats, portscan, icmp_flood, syn_burst, ssh_bf, logger, incident_mgr, notifier, dns_tunnel=None, http_bf=None, slow_loris=None, whitelist=None) -> None:
    if interface:
        print(f"[*] Live capture on interface: {interface}")
    else:
        print(f"[*] Live capture on default interface: {conf.iface}")

    def on_packet(pkt):
        try:
            handle_packet(
                pkt, stats, portscan, icmp_flood, syn_burst, ssh_bf,
                logger, incident_mgr, notifier,
                dns_tunnel, http_bf, slow_loris, whitelist,
            )
        except Exception as e:
            print(f"[!] Packet handler error: {e}", file=sys.stderr)
            traceback.print_exc()

    # "ip or arp" captures ARP frames as well as all IP traffic
    sniff(iface=interface, prn=on_packet, store=False, filter="ip or arp")


# -----------------------
# Summary
# -----------------------
# prints traffic stats when the IDS shuts down
# good for knowing how much traffic was seen during a session
def summarize(stats) -> None:
    def topn(d, n=5):
        return sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n]

    print("\n=== SUMMARY ===")
    print(f"Total packets : {stats['total_packets']}")
    print(f"IP packets    : {stats['ip_packets']}")
    print(f"TCP packets   : {stats['tcp_packets']}")
    print(f"UDP packets   : {stats['udp_packets']}")
    print(f"ICMP packets  : {stats['icmp_packets']}")
    print(f"Top src IPs   : {topn(stats['top_src'])}")
    print(f"Top dst IPs   : {topn(stats['top_dst'])}")


# -----------------------
# Entry point
# -----------------------
# parses CLI args, loads config.json, sets up all the detectors and components
# then kicks off either live capture or pcap replay
# thresholds in config.json take priority over CLI defaults
def main() -> int:
    ap = argparse.ArgumentParser(description="NetIDS — Network Intrusion Detection System")
    ap.add_argument("--pcap", default=None, help="Path to .pcap/.pcapng file")
    ap.add_argument("--live", action="store_true", help="Sniff live packets")
    ap.add_argument("--iface", default=None, help="Network interface (e.g. enp0s3)")
    ap.add_argument("--log", default="logs/alerts.jsonl", help="Alert output path (JSONL)")
    ap.add_argument("--config", default="config.json", help="Config file path")
    ap.add_argument("--window", type=int, default=15, help="Port-scan window (seconds)")
    ap.add_argument("--threshold", type=int, default=20, help="Port-scan distinct port threshold")
    ap.add_argument("--icmp-window", type=int, default=10, help="ICMP flood window (seconds)")
    ap.add_argument("--icmp-threshold", type=int, default=5, help="ICMP flood packet threshold")
    ap.add_argument("--syn-window", type=int, default=5, help="SYN burst window (seconds)")
    ap.add_argument("--syn-threshold", type=int, default=20, help="SYN burst packet threshold")
    ap.add_argument("--ssh-window", type=int, default=30, help="SSH brute-force window (seconds)")
    ap.add_argument("--ssh-threshold", type=int, default=12, help="SSH brute-force attempt threshold")
    ap.add_argument("--auto-block", action="store_true", help="Auto-block HIGH severity sources via iptables (requires root)")

    args = ap.parse_args()
    cfg = load_config(args.config)
    ROOT = Path(__file__).resolve().parents[1]

    # -----------------------
    # Component initialization
    # -----------------------
    # incident manager groups alerts from the same IP within a 120s window
    # incidents expire after 5 minutes of no activity from that source
    incident_mgr = IncidentManager(window_s=120, max_idle_s=300)
    notifier = Notifier(cooldown_s=20, auto_block_enabled=args.auto_block)

    whitelist = set(cfg.get("whitelist", []))
    if whitelist:
        print(f"[CFG] whitelist={sorted(whitelist)}")

    log_path = Path(cfg.get("log_path", args.log))
    if not log_path.is_absolute():
        log_path = ROOT / log_path
    logger = JSONLLogger(log_path)

    # -----------------------
    # Detector initialization
    # -----------------------
    # pull thresholds from config for each detector
    # we pass the medium threshold to the constructor since thats the main trigger point
    # low and high are stored on the detector and checked inside process()
    ps_cfg = cfg.get("port_scan", {})
    icmp_cfg = cfg.get("icmp_flood", {})
    syn_cfg = cfg.get("syn_burst", {})
    ssh_cfg = cfg.get("ssh_bruteforce", {})
    dns_cfg = cfg.get("dns_tunnel", {})
    http_cfg = cfg.get("http_bruteforce", {})
    loris_cfg = cfg.get("slow_loris", {})

    ps_thresholds = pick_thresholds(ps_cfg.get("thresholds", {}), args.threshold)
    icmp_thresholds = pick_thresholds(icmp_cfg.get("thresholds", {}), args.icmp_threshold)
    syn_thresholds = pick_thresholds(syn_cfg.get("thresholds", {}), args.syn_threshold)
    ssh_thresholds = pick_thresholds(ssh_cfg.get("thresholds", {}), args.ssh_threshold)
    dns_thresholds = pick_thresholds(dns_cfg.get("thresholds", {}), 30)
    http_thresholds = pick_thresholds(http_cfg.get("thresholds", {}), 20)
    loris_thresholds = pick_thresholds(loris_cfg.get("thresholds", {}), 20)

    portscan = PortScanDetector(
        window_s=_int(ps_cfg.get("window_s"), args.window),
        threshold_ports=ps_thresholds["medium"],
    )
    portscan.thresholds = ps_thresholds

    icmp_flood = ICMPFloodDetector(
        window_s=_int(icmp_cfg.get("window_s"), args.icmp_window),
        threshold_pkts=icmp_thresholds["medium"],
    )
    icmp_flood.thresholds = icmp_thresholds

    syn_burst = SYNBurstDetector(
        window_s=_int(syn_cfg.get("window_s"), args.syn_window),
        threshold_syn=syn_thresholds["medium"],
    )
    syn_burst.thresholds = syn_thresholds

    ssh_bf = SSHBruteForceDetector(
        window_s=_int(ssh_cfg.get("window_s"), args.ssh_window),
        threshold_hits=ssh_thresholds["medium"],
    )
    ssh_bf.thresholds = ssh_thresholds

    dns_tunnel = DNSTunnelDetector(
        window_s=_int(dns_cfg.get("window_s"), 10),
        threshold_queries=dns_thresholds["medium"],
    )
    dns_tunnel.thresholds = dns_thresholds

    http_bf = HTTPBruteForceDetector(
        window_s=_int(http_cfg.get("window_s"), 20),
        threshold_requests=http_thresholds["medium"],
    )
    http_bf.thresholds = http_thresholds

    slow_loris = SlowLorisDetector(
        threshold_connections=loris_thresholds["medium"],
    )
    slow_loris.thresholds = loris_thresholds

    print(f"[CFG] log_path={Path(log_path).resolve()}")
    print(f"[CFG] port_scan window_s={portscan.window_s} thresholds={portscan.thresholds}")
    print(f"[CFG] icmp_flood window_s={icmp_flood.window_s} thresholds={icmp_flood.thresholds}")
    print(f"[CFG] syn_burst window_s={syn_burst.window_s} thresholds={syn_burst.thresholds}")
    print(f"[CFG] ssh_bruteforce window_s={ssh_bf.window_s} thresholds={ssh_bf.thresholds}")
    print(f"[CFG] dns_tunnel window_s={dns_tunnel.window_s} thresholds={dns_tunnel.thresholds}")
    print(f"[CFG] http_bruteforce window_s={http_bf.window_s} thresholds={http_bf.thresholds}")
    print(f"[CFG] slow_loris thresholds={slow_loris.thresholds}")

    # -----------------------
    # Packet stats
    # -----------------------
    # just simple counters, gets printed at the end of a session
    stats = {
        "total_packets": 0,
        "ip_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "top_src": defaultdict(int),
        "top_dst": defaultdict(int),
    }

    # -----------------------
    # Run
    # -----------------------
    # kick off live capture or pcap replay, ctrl+c stops it cleanly
    try:
        if args.live:
            run_live(
                args.iface, stats, portscan, icmp_flood, syn_burst, ssh_bf,
                logger, incident_mgr, notifier,
                dns_tunnel, http_bf, slow_loris, whitelist,
            )
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
                handle_packet(
                    pkt, stats, portscan, icmp_flood, syn_burst, ssh_bf,
                    logger, incident_mgr, notifier,
                    dns_tunnel, http_bf, slow_loris, whitelist,
                )

    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    finally:
        summarize(stats)
        print(f"Alerts saved to: {Path(log_path).resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
