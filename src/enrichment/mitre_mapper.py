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
}


def map_mitre(alert_type):
    return MITRE_MAP.get(alert_type, "UNKNOWN")