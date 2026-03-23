MITRE_MAP = {
    "PORT_SCAN_SUSPECTED": "T1046",

    # ICMP flood — Network Denial of Service
    "ICMP_FLOOD_SUSPECTED": "T1498",
    "ICMP_FLOOD": "T1498",

    # ICMP sweep — Remote System Discovery (host enumeration, not DoS)
    "ICMP_SWEEP_SUSPECTED": "T1018",
    "ICMP_SWEEP": "T1018",

    # SYN burst / SYN flood — Network Denial of Service
    "SYN_BURST_SUSPECTED": "T1498",

    # SSH brute force — Brute Force
    "SSH_BRUTEFORCE_SUSPECTED": "T1110",
    "SSH_BRUTE_FORCE": "T1110",

    # ARP spoofing — Adversary-in-the-Middle
    "ARP_SPOOF_SUSPECTED": "T1557.002",

    # DNS tunneling — Application Layer Protocol: DNS
    "DNS_TUNNEL_SUSPECTED": "T1071.004",

    # HTTP brute force — Brute Force
    "HTTP_BRUTEFORCE_SUSPECTED": "T1110",

    # Slow Loris / slow HTTP — Network Denial of Service
    "SLOW_LORIS_SUSPECTED": "T1499",
}


def map_mitre(alert_type):
    return MITRE_MAP.get(alert_type, "UNKNOWN")