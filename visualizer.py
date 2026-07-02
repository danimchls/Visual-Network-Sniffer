import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec
import time
from collections import deque
from datetime import datetime
from sniffer import Sniffer
from scapy.all import rdpcap

class Visualizer:
    def __init__(self):
        self.sniffer = Sniffer()
        
        self.SNAPSHOT_INTERVAL = 5
        self.historico = {
            'TCP': deque(maxlen=20),
            'UDP': deque(maxlen=20),
            'ICMP': deque(maxlen=20),
            'ARP': deque(maxlen=20),
            'OTHER': deque(maxlen=20),
        }
        self.timestamps = deque(maxlen=20)
        self.recent_alerts = deque(maxlen=8)
        self.extra_stats = {
            'top_sources': [],
            'top_ports': [],
            'icmp_stats': {},
            'ttl_distribution': {},
        }

        self.DEFAULT_PPS = 5
        self.simulation_running = True
        self.total_packets = 0
        self.packets_processed = 0
        self.fig = None


    def snapshot_counts(self):
        snapshot = self.sniffer.get_snapshot()
        for proto in self.historico:
            self.historico[proto].append(snapshot.get(proto, 0))
        self.timestamps.append(datetime.now())

        results = self.sniffer.analyzer.snapshot()
        for alert in results.get('alerts', []):
            self.recent_alerts.append(alert)

        self.extra_stats['top_sources'] = results.get('top_sources', [])
        self.extra_stats['top_ports'] = results.get('top_ports', [])
        self.extra_stats['icmp_stats'] = results.get('icmp_stats', {})
        self.extra_stats['ttl_distribution'] = results.get('ttl_distribution', {})


    def background_counter(self):
        while self.simulation_running:
            time.sleep(self.SNAPSHOT_INTERVAL)
            if self.simulation_running:
                self.snapshot_counts()


    def pcap_feeder(self, filepath, pps):

        packets = rdpcap(filepath)
        self.total_packets = len(packets)
        delay = 1.0 / pps

        print(f"  PCAP: {filepath}")
        print(f"  Pacotes: {self.total_packets}")
        print(f"  Taxa simulada: {pps} pacotes/segundo (delay={delay:.2f}s)")
        print(f"  Duracao estimada: {self.total_packets / pps:.1f}s")
        print()

        start_time = time.perf_counter()
        for i, pkt in enumerate(packets):
            if not self.simulation_running:
                break
            self.sniffer.process_packet(pkt)
            self.packets_processed = i + 1

            # Compensa o tempo de processamento para manter a taxa desejada de
            # pacotes por segundo de forma mais precisa.
            next_time = start_time + (i + 1) * delay
            sleep_time = next_time - time.perf_counter()
            if sleep_time > 0:
                time.sleep(sleep_time)


        print(f"\n  [PCAP] Todos os {self.total_packets} pacotes processados.")
        print(f"  Fechando visualizador em 15s...")
        time.sleep(15)
        self.simulation_running = False
        plt.close('all')
        

    def animate(self, i):
        self.fig.clf()

        gs = GridSpec(2, 2, figure=self.fig, height_ratios=[2, 1], hspace=0.45, wspace=0.35)
        ax_main = self.fig.add_subplot(gs[0, :])
        ax_top = self.fig.add_subplot(gs[1, 0])
        ax_alerts = self.fig.add_subplot(gs[1, 1])

        colors = {
            'TCP': '#1f77b4',
            'UDP': '#ff7f0e',
            'ICMP': '#2ca02c',
            'ARP': '#d62728',
            'OTHER': '#9467bd',
        }

        active_protos = [p for p in self.historico if any(self.historico[p])]
        for proto in active_protos:
            ax_main.plot(
                list(self.timestamps), list(self.historico[proto]),
                label=proto, color=colors.get(proto, 'black'), linewidth=2
            )

        total_all = sum(sum(self.historico[p]) for p in self.historico)
        total_tcp = sum(self.historico['TCP'])
        total_udp = sum(self.historico['UDP'])
        total_icmp = sum(self.historico['ICMP'])
        total_arp = sum(self.historico['ARP'])

        pps = self.DEFAULT_PPS
        if pps > 0:
            title = (
                f"Simulacao PCAP  |  Taxa: {pps} pkt/s  | snap-interval: {self.SNAPSHOT_INTERVAL } | "
                f"Progresso: {self.packets_processed}/{self.total_packets}\n"
                f"Total: {total_all} | TCP: {total_tcp} | UDP: {total_udp} | ICMP: {total_icmp} | ARP: {total_arp}"
            )
        else:
            title = (
                f"Trafego de Pacotes (ultimos {self.SNAPSHOT_INTERVAL * max(len(self.timestamps), 1)}s)\n"
                f"Total: {total_all} | TCP: {total_tcp} | UDP: {total_udp} | ICMP: {total_icmp} | ARP: {total_arp} "
            )
        ax_main.set_title(title, fontsize=11, fontweight='bold')
        ax_main.set_xlabel('Tempo', fontsize=9)
        ax_main.set_ylabel('Pacotes por intervalo', fontsize=9)
        ax_main.tick_params(axis='x', rotation=45, labelsize=7)
        ax_main.tick_params(axis='y', labelsize=7)
        ax_main.grid(True, linestyle='--', alpha=0.4)
        if active_protos:
            ax_main.legend(loc='upper left', framealpha=0.7, fontsize=7)

        top_src = self.extra_stats.get('top_sources', [])
        if top_src:
            ips = [ip[:15] for ip, _ in top_src[:8]]
            vals = [v for _, v in top_src[:8]]
            bars = ax_top.barh(ips[::-1], vals[::-1], color='steelblue', edgecolor='white')
            for bar, val in zip(bars, vals[::-1]):
                ax_top.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height() / 2,
                            str(val), va='center', fontsize=7)
        ax_top.set_title('Top IPs Origem (por intervalo)', fontsize=10, fontweight='bold')
        ax_top.set_xlabel('Pacotes', fontsize=8)
        ax_top.tick_params(labelsize=7)
        ax_top.grid(True, linestyle='--', alpha=0.3, axis='x')

        ax_alerts.axis('off')
        ax_alerts.set_title('Alertas de Seguranca', fontsize=10, fontweight='bold', color='darkred')

        lines = []
        if self.recent_alerts:
            lines.append('Alertas recentes:\n')
            for alert in list(self.recent_alerts)[-6:]:
                lines.append(f'  {alert}')
        else:
            lines.append('(nenhum alerta detectado)')

        icmp = self.extra_stats.get('icmp_stats', {})
        if icmp:
            lines.append('\nICMP (tipo/codigo):')
            for name, count in sorted(icmp.items(), key=lambda x: x[1], reverse=True)[:11]:
                lines.append(f'  {name}: {count}')

        ttl = self.extra_stats.get('ttl_distribution', {})
        if ttl:
            lines.append('\nTTL / SO possivel:')
            for key, count in sorted(ttl.items(), key=lambda x: x[1], reverse=True)[:5]:
                lines.append(f'  {key}: {count}')

        top_ports = self.extra_stats.get('top_ports', [])
        if top_ports:
            lines.append('\nTop Portas Destino:')
            for port, count in top_ports[:4]:
                lines.append(f'  Porta {port}: {count}')

        text_str = '\n'.join(lines)
        ax_alerts.text(0.02, 0.98, text_str, transform=ax_alerts.transAxes,
                    fontsize=7.5, fontfamily='monospace', verticalalignment='top',
                    bbox=dict(boxstyle='round,pad=0.5', facecolor='lightyellow', alpha=0.9))


