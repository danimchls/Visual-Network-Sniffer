from scapy.all import sniff, IP, ARP
from collections import defaultdict
import threading
from analyzer import SecurityAnalyzer


class Sniffer:
    def __init__(self):
        self.protocol_counts = defaultdict(int)
        self.counts_lock = threading.Lock()
        self.analyzer = SecurityAnalyzer()

    def process_packet(self, pkt):
        with self.counts_lock:
            if IP in pkt:
                proto = pkt[IP].proto
                if proto == 6:
                    self.protocol_counts['TCP'] += 1
                elif proto == 17:
                        self.protocol_counts['UDP'] += 1
                elif proto == 1:
                    self.protocol_counts['ICMP'] += 1
                else:
                    self.protocol_counts['OTHER'] += 1
                print(f"TTL: {pkt[IP].ttl}")

            if ARP in pkt:
                self.protocol_counts['ARP'] += 1

            if not IP in pkt and not ARP in pkt:
                self.protocol_counts['OTHER'] += 1
                
        print(f"Packet captured: {pkt.summary()}")
        self.analyzer.process_packet(pkt)
        
        
    def get_snapshot(self):
        with self.counts_lock:
            snapshot = dict(self.protocol_counts)
            self.protocol_counts.clear()
        return snapshot

    def start_sniffing(self):
        try:
            sniff(prn=self.process_packet, store=False)
        except PermissionError:
            print("Erro: Permissão negada. Execute o script com privilégios de administrador (sudo).")


