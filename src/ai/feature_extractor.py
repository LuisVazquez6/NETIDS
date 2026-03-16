from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP


class FeatureExtractor:
    """
    Extracts packet-level and lightweight source-based rolling features
    for anomaly detection.
    """

    def __init__(self):
        self.src_packet_count = defaultdict(int)
        self.src_byte_count = defaultdict(int)
        self.src_dst_ports = defaultdict(set)
        self.src_syn_count = defaultdict(int)
        self.src_icmp_count = defaultdict(int)

    def extract(self, pkt):
        """
        Returns a feature dictionary or None if packet is not IP-based.
        """
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = int(ip.proto)
        packet_length = len(pkt)

        src_port = 0
        dst_port = 0
        tcp_flags = 0
        is_syn = 0
        is_icmp = 0

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = int(tcp.flags)

            if tcp.flags & 0x02:  # SYN
                is_syn = 1
                self.src_syn_count[src_ip] += 1

            self.src_dst_ports[src_ip].add(dst_port)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            self.src_dst_ports[src_ip].add(dst_port)

        elif pkt.haslayer(ICMP):
            is_icmp = 1
            self.src_icmp_count[src_ip] += 1

        self.src_packet_count[src_ip] += 1
        self.src_byte_count[src_ip] += packet_length

        features = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "packet_length": packet_length,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "src_packet_count": self.src_packet_count[src_ip],
            "src_byte_count": self.src_byte_count[src_ip],
            "unique_dst_ports": len(self.src_dst_ports[src_ip]),
            "syn_count": self.src_syn_count[src_ip],
            "icmp_count": self.src_icmp_count[src_ip],
            "is_syn": is_syn,
            "is_icmp": is_icmp,
        }

        return features