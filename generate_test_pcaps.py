import os
from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, wrpcap

OUTPUT_DIR = "test_pcaps"
DEFAULT_SRC_MAC = "02:00:00:00:00:01"
DEFAULT_DST_MAC = "02:00:00:00:00:02"
os.makedirs(OUTPUT_DIR, exist_ok=True)

def generate_port_scan():
    print("[1/5] Gerando port_scan.pcap ...")
    packets = []
    for port in range(1, 21):
        pkt = Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="10.0.0.100", dst="192.168.1.1", ttl=64) / TCP(
            sport=54321, dport=port, flags="S", seq=1000 + port
        )
        packets.append(pkt)
    synack = Ether(src=DEFAULT_DST_MAC, dst=DEFAULT_SRC_MAC) / IP(src="192.168.1.1", dst="10.0.0.100", ttl=128) / TCP(
        sport=18, dport=54321, flags="SA", seq=5000, ack=1001
    )
    packets.append(synack)
    wrpcap(os.path.join(OUTPUT_DIR, "port_scan.pcap"), packets)
    print(f"  -> {len(packets)} pacotes (20 SYN + 1 SYN-ACK)")

def generate_syn_flood():
    print("[2/5] Gerando syn_flood.pcap ...")
    packets = []
    victim_ip = "192.168.1.1"
    attacker_ip = "10.0.0.100"
    for seq in range(1, 301):
        pkt = Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src=attacker_ip, dst=victim_ip, ttl=64) / TCP(
            sport=40000 + (seq % 1000), dport=80, flags="S", seq=1000 + seq
        )
        packets.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "syn_flood.pcap"), packets)
    print(f"  -> {len(packets)} pacotes (300 SYN sem resposta)")

def generate_arp_spoof():
    print("[3/5] Gerando arp_spoof.pcap ...")
    packets = []
    arp_reply_1 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:11:22:33", psrc="192.168.1.1",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.100"
    )
    packets.append(arp_reply_1)
    arp_reply_2 = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2, hwsrc="aa:bb:cc:44:55:66", psrc="192.168.1.1",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.100"
    )
    packets.append(arp_reply_2)
    wrpcap(os.path.join(OUTPUT_DIR, "arp_spoof.pcap"), packets)
    print(f"  -> {len(packets)} pacotes (2 ARP replies conflitantes)")

def generate_icmp_variety():
    print("[4/5] Gerando icmp_variety.pcap ...")
    packets = []
    tests = [
        (8, 0, "Echo Request"),
        (0, 0, "Echo Reply"),
        (3, 1, "Dest Unreachable - Host"),
        (3, 3, "Dest Unreachable - Port"),
        (11, 0, "TTL Exceeded - Transit"),
        (3, 0, "Dest Unreachable - Net"),
        (5, 1, "Redirect - Host"),
        (13, 0, "Timestamp Request"),
        (14, 0, "Timestamp Reply"),
        (8, 0, "Echo Request (2)"),
        (0, 0, "Echo Reply (2)"),
    ]
    for icmp_type, icmp_code, desc in tests:
        pkt = Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64) / ICMP(
            type=icmp_type, code=icmp_code, id=1, seq=len(packets)
        )
        packets.append(pkt)
    wrpcap(os.path.join(OUTPUT_DIR, "icmp_variety.pcap"), packets)
    print(f"  -> {len(packets)} pacotes ICMP ({len(set((t, c) for t, c, _ in tests))} tipos distintos)")

def generate_normal_traffic():
    print("[5/5] Gerando normal_traffic.pcap ...")
    packets = []
    # TCP 3-way handshake
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="93.184.216.34", ttl=64) /
                   TCP(sport=45678, dport=80, flags="S", seq=1000))
    packets.append(Ether(src=DEFAULT_DST_MAC, dst=DEFAULT_SRC_MAC) / IP(src="93.184.216.34", dst="192.168.1.100", ttl=52) /
                   TCP(sport=80, dport=45678, flags="SA", seq=5000, ack=1001))
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="93.184.216.34", ttl=64) /
                   TCP(sport=45678, dport=80, flags="A", seq=1001, ack=5001))
    # HTTP GET
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="93.184.216.34", ttl=64) /
                   TCP(sport=45678, dport=80, flags="PA", seq=1001, ack=5001))
    # HTTP response
    packets.append(Ether(src=DEFAULT_DST_MAC, dst=DEFAULT_SRC_MAC) / IP(src="93.184.216.34", dst="192.168.1.100", ttl=52) /
                   TCP(sport=80, dport=45678, flags="PA", seq=5001, ack=1100))
    # DNS query (UDP)
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="8.8.8.8", ttl=64) /
                   UDP(sport=54321, dport=53))
    # DNS response (UDP)
    packets.append(Ether(src=DEFAULT_DST_MAC, dst=DEFAULT_SRC_MAC) / IP(src="8.8.8.8", dst="192.168.1.100", ttl=116) /
                   UDP(sport=53, dport=54321))
    # ARP request (normal)
    packets.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.100",
        hwdst="00:00:00:00:00:00", pdst="192.168.1.1"
    ))
    # ARP reply (normal)
    packets.append(Ether(dst="aa:bb:cc:dd:ee:ff") / ARP(
        op=2, hwsrc="11:22:33:44:55:66", psrc="192.168.1.1",
        hwdst="aa:bb:cc:dd:ee:ff", pdst="192.168.1.100"
    ))
    # SSH traffic (port 22)
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="10.0.0.50", ttl=64) /
                   TCP(sport=40000, dport=22, flags="PA", seq=2000, ack=6000))
    # HTTPS traffic (port 443)
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="192.168.1.100", dst="142.250.80.4", ttl=64) /
                   TCP(sport=40001, dport=443, flags="PA", seq=3000, ack=7000))
    # Windows machine traffic (TTL=128)
    packets.append(Ether(src=DEFAULT_SRC_MAC, dst=DEFAULT_DST_MAC) / IP(src="10.0.0.200", dst="10.0.0.1", ttl=128) /
                   TCP(sport=50000, dport=445, flags="A", seq=4000, ack=8000))
    wrpcap(os.path.join(OUTPUT_DIR, "normal_traffic.pcap"), packets)
    print(f"  -> {len(packets)} pacotes (TCP handshake, HTTP, DNS, ARP, SSH, HTTPS)")

if __name__ == "__main__":
    print("Gerando arquivos PCAP de teste em", OUTPUT_DIR)
    print()
    generate_port_scan()
    generate_syn_flood()
    generate_arp_spoof()
    generate_icmp_variety()
    generate_normal_traffic()
    print()
    print("Arquivos gerados:")
    for f in sorted(os.listdir(OUTPUT_DIR)):
        size = os.path.getsize(os.path.join(OUTPUT_DIR, f))
        print(f"  {f} ({size} bytes)")
