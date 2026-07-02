import threading
import time
from collections import defaultdict
from scapy.all import IP, TCP, UDP, ICMP, ARP, deque


class PortScanDetector:
    def __init__(self, threshold=10, window_seconds=5):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # IP origem -> IP destino -> porta destino -> timestamp
        self._src_ports = defaultdict(lambda: defaultdict(dict))
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        """Guarda o instante que um IP solicitou (SYN) uma porta destino, 
        e verifica se o número de portas distintas solicitadas por um IP, 
        em um intervalo de tempo (window_seconds), excede o limiar.
        """
        if IP not in pkt or TCP not in pkt:
            return
        flags = pkt[TCP].flags
        if not (flags & 0x02): # SYN flag is not set
            return
        if flags & 0x10: # ACK flag is set, ignore ACK packets
            return
        src = pkt[IP].src
        dport = pkt[TCP].dport
        dst= pkt[IP].dst

        with self._lock:
            now = float(pkt.time)
            
            ports = self._src_ports[src][dst]

            # Atualiza o instante em que a porta foi acessada
            ports[dport] = now

            # Remove portas expiradas
            for port in list(ports.keys()):
                if now - ports[port] > self.window_seconds:
                    del ports[port]

            count = len(ports)

            if count >= self.threshold:
                self.alerts.append(
                    f"[PORT SCAN] src:{src} dst:{dst} -> "
                    f"{count} portas distintas (SYN)"
                )

    def snapshot(self):
        with self._lock:
            alerts = self.alerts[:]
            self.alerts.clear()
        return alerts
    

class SynFloodDetector:
    def __init__(self, threshold=100, window_seconds=5, completion_ratio=0.5):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.completion_ratio = completion_ratio 
        # IP origem -> {(IP destino, sport, dport): instante_do_SYN}
        self._pending_connections = defaultdict(dict)
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        """Guarda o instante que um IP por uma porta (sport) solicitou (SYN) uma porta destino(dport),
        enquanto aquela requisição não enviar um ACK final a conexão é considerada meio-aberta.
        Alerta quando o número de conexões meio-abertas (SYN sem ACK) de um IP,
        em um intervalo de tempo (window_seconds), excede o limiar.
        """
        if IP not in pkt or TCP not in pkt:
            return
        flags = pkt[TCP].flags
        src = pkt[IP].src
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        dst = pkt[IP].dst
        now = float(pkt.time)

        with self._lock:
            pending = self._pending_connections[src]

            # Remove conexões antigas
            for conn, timestamp in list(pending.items()):
                if now - timestamp > self.window_seconds:
                    del pending[conn]

            # Recebeu um SYN (sem ACK)
            if flags & 0x02 and not flags & 0x10:
                pending[(dst, sport, dport)] = now

            # Recebeu o ACK final
            elif flags & 0x10 and not flags & 0x02:
                pending.pop((dst, sport, dport), None)

            # Quantidade de conexões meio-abertas
            half_open = len(pending)

            if half_open >= self.threshold:
                self.alerts.append(
                    f"[SYN FLOOD] {src} -> possui "
                    f"{half_open} conexões meio-abertas. "
                    f"(limiar={self.threshold})"
                )

    def snapshot(self):
        with self._lock:
            alerts = self.alerts[:]
            self.alerts.clear()
        return alerts


class ArpSpoofDetector:
    def __init__(self, window_seconds=5):
        self.window_seconds = window_seconds
        # IP consultado -> instante do último ARP Request
        self._pending_requests = {}
        self.alerts = []
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        """Detecta ARP Replies não solicitados, ou seja, quando um IP responde a uma consulta ARP que não foi feita por ele.
        """
        if ARP not in pkt:
            return

        arp = pkt[ARP]
        now = float(pkt.time)

        with self._lock:

            # Remove requests expirados
            for ip, timestamp in list(self._pending_requests.items()):
                if now - timestamp > self.window_seconds:
                    del self._pending_requests[ip]

            # ARP Request
            if arp.op == 1:
                # pdst = IP que está sendo consultado
                self._pending_requests[arp.pdst] = now

            # ARP Reply
            elif arp.op == 2:
                # psrc = IP que está respondendo
                if arp.psrc not in self._pending_requests:
                    self.alerts.append(
                        f"[ARP SPOOF] ARP Reply não solicitado: "
                        f"tentativa de associar {arp.psrc} ao MAC {arp.hwsrc}"
                    )
                else:
                    # Request atendido
                    del self._pending_requests[arp.psrc]

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
        self._port_counts = defaultdict(int)
        self._lock = threading.Lock()

    def process_packet(self, pkt):
        if IP not in pkt or TCP not in pkt:
            return
                
        with self._lock:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dstport=pkt[TCP].dport

            self._src_counts[src] += 1
            self._port_counts[(dst, dstport)] += 1

    def snapshot(self):
        with self._lock:
            top_src = sorted(self._src_counts.items(), key=lambda x: x[1], reverse=True)[:self.max_entries]
            top_ports = sorted(self._port_counts.items(), key=lambda x: x[1], reverse=True)[:self.max_entries]
            self._src_counts.clear()
            self._port_counts.clear()
        return top_src, top_ports


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
        if IP not in pkt or TCP not in pkt:
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
        self.port_scanner = PortScanDetector(threshold=10, window_seconds=5)
        self.syn_flood = SynFloodDetector(threshold=50, window_seconds=5)
        self.arp_spoof = ArpSpoofDetector(window_seconds=10)
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
        top_src, top_ports= self.top_talkers.snapshot()
        ttl_data = self.ttl.snapshot()

        return {
            'alerts': alerts,
            'icmp_stats': icmp_stats,
            'top_sources': top_src,
            'top_ports': top_ports,
            'ttl_distribution': ttl_data,
        }
