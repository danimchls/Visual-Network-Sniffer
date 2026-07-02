import threading
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, ARP


class PortScanDetector:
    def __init__(self, threshold=15, window_seconds=10):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._src_ports = defaultdict(set)
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return
        flags = pkt[TCP].flags
        if not (flags & 0x02):  # SYN
            return
        if flags & 0x10:       # ACK
            return
        src = pkt[IP].src
        dport = pkt[TCP].dport
        with self._lock:
            if src in self._src_ports and dport in self._src_ports[src]:
                return
            self._src_ports[src].add(dport)
            count = len(self._src_ports[src])
            if count == self.threshold or (count > self.threshold and count % 10 == 0):
                self.alerts.append(
                    f"[PORT SCAN] {src} -> {count} portas distintas (SYN)"
                )

    def snapshot(self):
        with self._lock:
            alerts = self.alerts[:]
            self.alerts.clear()
        return alerts


class SynFloodDetector:
    def __init__(self, threshold=200, window_seconds=5, completion_ratio=0.5):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.completion_ratio = completion_ratio
        self._syn_counts = defaultdict(int)
        self._ack_counts = defaultdict(int)
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return
        flags = pkt[TCP].flags
        src = pkt[IP].src
        
        with self._lock:
            # Count pure SYN packets (SYN without ACK)
            if (flags & 0x02) and not (flags & 0x10):
                self._syn_counts[src] += 1
            # Count ACK packets (connection completions)
            elif flags & 0x10:
                self._ack_counts[src] += 1

    def snapshot(self):
        with self._lock:
            alerts = []
            for src in self._syn_counts:
                syn_count = self._syn_counts[src]
                ack_count = self._ack_counts.get(src, 0)
                
                if syn_count > self.threshold:
                    ratio = ack_count / syn_count if syn_count > 0 else 0
                    
                    if ratio < self.completion_ratio:
                        alerts.append(
                            f"[SYN FLOOD] {src} -> {syn_count} SYN, {ack_count} ACK "
                            f"(taxa={ratio:.2%}, limiar={self.threshold})"
                        )
            
            self._syn_counts.clear()
            self._ack_counts.clear()
            self.alerts = alerts
        return alerts


class ArpSpoofDetector:
    def __init__(self):
        self._ip_mac_map = {}
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if ARP not in pkt:
            return
        op = pkt[ARP].op
        if op != 2:
            return
        psrc = pkt[ARP].psrc
        hwsrc = pkt[ARP].hwsrc
        with self._lock:
            if psrc in self._ip_mac_map and self._ip_mac_map[psrc] != hwsrc:
                self.alerts.append(
                    f"[ARP SPOOF] IP {psrc} associado a MACs diferentes: "
                    f"{self._ip_mac_map[psrc]} e {hwsrc}"
                )
            self._ip_mac_map[psrc] = hwsrc

    def snapshot(self):
        with self._lock:
            alerts = self.alerts[:]
            self.alerts.clear()
        return alerts


class IcmpAnalyzer:
    TYPE_NAMES = {
        (0, 0): "Echo Reply",
        (3, 0): "Net Unreachable",
        (3, 1): "Host Unreachable",
        (3, 3): "Port Unreachable",
        (4, 0): "Source Quench",
        (5, 0): "Redirect Net",
        (5, 1): "Redirect Host",
        (8, 0): "Echo Request",
        (11, 0): "TTL Exceeded Transmit",
        (11, 1): "TTL Exceeded Reassem",
        (13, 0): "Timestamp Request",
        (14, 0): "Timestamp Reply",
    }

    def __init__(self):
        self._type_counts = defaultdict(int)
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt or ICMP not in pkt:
            return
        icmp_type = pkt[ICMP].type
        icmp_code = pkt[ICMP].code
        with self._lock:
            self._type_counts[(icmp_type, icmp_code)] += 1

    def snapshot(self):
        with self._lock:
            stats = {}
            for (t, c), count in self._type_counts.items():
                name = self.TYPE_NAMES.get((t, c), f"Type {t}/Code {c}")
                stats[name] = count
            self._type_counts.clear()
        return stats


class TopTalkers:
    def __init__(self, max_entries=10):
        self.max_entries = max_entries
        self._src_counts = defaultdict(int)
        self._dst_counts = defaultdict(int)
        self._port_counts = defaultdict(int)
        self._proto_counts = defaultdict(int)
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt:
            if ARP in pkt:
                with self._lock:
                    self._proto_counts['ARP'] += 1
            return

        with self._lock:
            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto

            self._src_counts[src] += 1
            self._dst_counts[dst] += 1

            if proto == 6:
                self._proto_counts['TCP'] += 1
                if TCP in pkt:
                    self._port_counts[pkt[TCP].dport] += 1
            elif proto == 17:
                self._proto_counts['UDP'] += 1
                if UDP in pkt:
                    self._port_counts[pkt[UDP].dport] += 1
            elif proto == 1:
                self._proto_counts['ICMP'] += 1
            else:
                self._proto_counts[f'IP-{proto}'] += 1

    def get_top_sources(self):
        with self._lock:
            sorted_ips = sorted(self._src_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:self.max_entries]

    def get_top_ports(self):
        with self._lock:
            sorted_ports = sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ports[:self.max_entries]

    def get_proto_distribution(self):
        with self._lock:
            return dict(self._proto_counts)

    def snapshot(self):
        with self._lock:
            top_src = sorted(self._src_counts.items(), key=lambda x: x[1], reverse=True)[:self.max_entries]
            top_ports = sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)[:self.max_entries]
            proto_dist = dict(self._proto_counts)
            self._src_counts.clear()
            self._dst_counts.clear()
            self._port_counts.clear()
            self._proto_counts.clear()
        return top_src, top_ports, proto_dist


class TtlAnalyzer:
    TTL_HINTS = {
        64:  "Linux/Unix (64)",
        128: "Windows (128)",
        255: "Unix/BSD (255)",
        32:  "Windows 95 (32)",
        60:  "AIX (60)",
        30:  "Solaris (30)",
    }

    def __init__(self):
        self._ttl_counts = defaultdict(int)
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt:
            return
        ttl = pkt[IP].ttl
        with self._lock:
            self._ttl_counts[ttl] += 1

    def snapshot(self):
        with self._lock:
            ttl_data = {}
            for ttl, count in sorted(self._ttl_counts.items()):
                hint = self.TTL_HINTS.get(ttl, "")
                key = f"TTL={ttl}" + (f" ({hint})" if hint else "")
                ttl_data[key] = count
            self._ttl_counts.clear()
        return ttl_data


class SecurityAnalyzer:
    def __init__(self):
        self.port_scanner = PortScanDetector(threshold=15, window_seconds=10)
        self.syn_flood = SynFloodDetector(threshold=200, window_seconds=5)
        self.arp_spoof = ArpSpoofDetector()
        self.icmp = IcmpAnalyzer()
        self.top_talkers = TopTalkers(max_entries=10)
        self.ttl = TtlAnalyzer()

    def process_packet(self, pkt):
        self.port_scanner.process_packet(pkt)
        self.syn_flood.process_packet(pkt)
        self.arp_spoof.process_packet(pkt)
        self.icmp.process_packet(pkt)
        self.top_talkers.process_packet(pkt)
        self.ttl.process_packet(pkt)

    def snapshot(self):
        alerts = []
        alerts += self.port_scanner.snapshot()
        alerts += self.syn_flood.snapshot()
        alerts += self.arp_spoof.snapshot()

        icmp_stats = self.icmp.snapshot()
        top_src, top_ports, proto_dist = self.top_talkers.snapshot()
        ttl_data = self.ttl.snapshot()

        return {
            'alerts': alerts,
            'icmp_stats': icmp_stats,
            'top_sources': top_src,
            'top_ports': top_ports,
            'proto_distribution': proto_dist,
            'ttl_distribution': ttl_data,
        }
