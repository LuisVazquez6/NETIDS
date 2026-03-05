MITRE_MAP = {
    "PORT_SCAN_SUSPECTED": "T1046",

    # ICMP flood detector output
    "ICMP_FLOOD_SUSPECTED": "T1498",
    "ICMP_FLOOD": "T1498",

    # SYN burst output (already working)
    "SYN_BURST_SUSPECTED": "T1498",

    # SSH brute force detector output
    "SSH_BRUTEFORCE_SUSPECTED": "T1110",
    "SSH_BRUTE_FORCE": "T1110",
}

def map_mitre(alert_type):
    return MITRE_MAP.get(alert_type, "UNKNOWN")