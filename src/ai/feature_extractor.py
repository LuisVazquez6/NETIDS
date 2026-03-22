import time
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Per-source state resets after this many seconds of inactivity.
_WINDOW_S = 60


class _SrcState:
    __slots__ = ("packet_count", "byte_count", "dst_ports", "syn_count", "icmp_count", "last_seen")

    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.dst_ports: set = set()
        self.syn_count = 0
        self.icmp_count = 0
        self.last_seen = 0.0


class FeatureExtractor:
    """
    Extracts packet-level and lightweight source-based rolling features
    for anomaly detection.

    Per-source counters reset after _WINDOW_S seconds of inactivity so
    they never grow unbounded during long-running captures.
    """

    def __init__(self, window_s: int = _WINDOW_S):
        self.window_s = window_s
        self._state: dict[str, _SrcState] = {}

    def _get_state(self, src_ip: str, now: float) -> _SrcState:
        st = self._state.get(src_ip)
        if st is None or (now - st.last_seen) > self.window_s:
            st = _SrcState()
            self._state[src_ip] = st
        return st

    def extract(self, pkt):
        """
        Returns a feature dictionary or None if packet is not IP-based.
        """
        if not pkt.haslayer(IP):
            return None

        now = float(getattr(pkt, "time", time.time()))
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

        st = self._get_state(src_ip, now)

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            tcp_flags = int(tcp.flags)

            if tcp.flags & 0x02:  # SYN
                is_syn = 1
                st.syn_count += 1

            st.dst_ports.add(dst_port)

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            src_port = int(udp.sport)
            dst_port = int(udp.dport)
            st.dst_ports.add(dst_port)

        elif pkt.haslayer(ICMP):
            is_icmp = 1
            st.icmp_count += 1

        st.packet_count += 1
        st.byte_count += packet_length
        st.last_seen = now

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "packet_length": packet_length,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "src_packet_count": st.packet_count,
            "src_byte_count": st.byte_count,
            "unique_dst_ports": len(st.dst_ports),
            "syn_count": st.syn_count,
            "icmp_count": st.icmp_count,
            "is_syn": is_syn,
            "is_icmp": is_icmp,
        }
